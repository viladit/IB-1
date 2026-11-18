import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

import jwt
import pytest
from argon2 import PasswordHasher

from app import AUDIENCE, ISSUER, create_app


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    path = tmp_path_factory.mktemp("ib1") / "db.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": path, "JWT_SECRET": secrets.token_hex(32)})
    password = secrets.token_urlsafe(24)
    runner = app.test_cli_runner()
    for username in ("reader-a", "reader-b"):
        result = runner.invoke(args=["create-user", username], input=f"{password}\n{password}\n")
        assert result.exit_code == 0, result.output
    return app, password


def sign_in(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


@pytest.fixture
def sessions(demo):
    app, password = demo
    client = app.test_client()
    headers = []
    for username in ("reader-a", "reader-b"):
        response = sign_in(client, username, password)
        assert response.status_code == 200
        headers.append({"Authorization": f"Bearer {response.json['access_token']}"})
    return client, *headers


def test_login_and_password_storage(demo):
    app, password = demo
    client = app.test_client()
    response = sign_in(client, "reader-a", password)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["token_type"] == "Bearer"
    assert response.json["expires_in"] == 900
    claims = jwt.decode(
        response.json["access_token"],
        app.config["JWT_SECRET"],
        algorithms=["HS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
    )
    assert claims["sub"] == "1"
    assert claims["exp"] - claims["iat"] == 900
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        rows = connection.execute("SELECT password_hash FROM users ORDER BY id")
        first, second = [row[0] for row in rows]
    assert first.startswith("$argon2id$")
    assert first != password and first != second
    assert PasswordHasher().verify(first, password)

    bad_password = sign_in(client, "reader-a", secrets.token_urlsafe(24))
    unknown_user = sign_in(client, "reader-a's colleague", password)
    assert bad_password.status_code == unknown_user.status_code == 401
    assert bad_password.json == unknown_user.json


@pytest.mark.parametrize(
    "kind",
    ["missing", "expired", "wrong-key", "wrong-audience", "wrong-issuer", "wrong-algorithm",
     "missing-exp"],
)
def test_protected_methods_require_valid_token(demo, kind):
    app, _ = demo
    client = app.test_client()
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"sub": "1", "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 900}
    key = app.config["JWT_SECRET"]
    algorithm = "HS256"
    if kind == "expired":
        claims.update(iat=now - 901, exp=now - 1)
    elif kind == "wrong-key":
        key = secrets.token_hex(32)
    elif kind == "wrong-audience":
        claims["aud"] = "another-service"
    elif kind == "wrong-issuer":
        claims["iss"] = "another-issuer"
    elif kind == "wrong-algorithm":
        algorithm = "HS384"
    elif kind == "missing-exp":
        claims.pop("exp")
    headers = {}
    if kind != "missing":
        token = jwt.encode(claims, key, algorithm=algorithm)
        headers = {"Authorization": f"Bearer {token}"}
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM notes").fetchone()
        assert client.get("/api/data", headers=headers).status_code == 401
        denied = client.post("/api/data", headers=headers, json={"body": "Draft"})
        assert denied.status_code == 401
        assert denied.headers["WWW-Authenticate"] == "Bearer"
        assert connection.execute("SELECT COUNT(*) FROM notes").fetchone() == count


def test_notes_are_private_and_escaped_once(demo, sessions):
    app, _ = demo
    client, alice, bob = sessions
    text = """<b>Example</b> & Bob's "note" """
    expected = "&lt;b&gt;Example&lt;/b&gt; &amp; Bob&#39;s &#34;note&#34; "
    created = client.post("/api/data", headers=alice, json={"body": text})
    assert created.status_code == 201
    assert created.json["body_html"] == expected
    assert created.mimetype == "application/json"
    assert created.headers["X-Content-Type-Options"] == "nosniff"

    first_list = client.get("/api/data", headers=alice)
    assert first_list.status_code == 200
    assert created.json in first_list.json["items"]
    assert created.json not in client.get("/api/data", headers=bob).json["items"]
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection:
        stored = connection.execute(
            "SELECT user_id, body FROM notes WHERE id = ?", (created.json["id"],)
        ).fetchone()
    assert stored == (1, text)


@pytest.mark.parametrize(
    "body",
    [{"body": ""}, {"body": " "}, {"body": 42}, {"body": "x" * 1001},
     {"body": "Note", "user_id": 2}, {"body": "\ud800"}],
)
def test_invalid_notes_return_json_error(sessions, body):
    client, alice, _ = sessions
    response = client.post("/api/data", headers=alice, json=body)
    assert response.status_code == 400
    assert isinstance(response.json["error"], str)


def test_malformed_and_oversized_json(sessions):
    client, alice, _ = sessions
    malformed = client.post("/auth/login", data="{", content_type="application/json")
    assert malformed.status_code == 400
    oversized = client.post("/api/data", headers=alice, json={"body": "x" * 17000})
    assert oversized.status_code == 413
    assert oversized.json == {"error": "Request body is too large"}


def test_missing_signing_key_fails_to_start(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        create_app()
