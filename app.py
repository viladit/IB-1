import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, g, jsonify, request
from markupsafe import escape

ISSUER = "ib-1"
AUDIENCE = "ib-1-notes"
AUTH_SCHEME = "Bearer"
TOKEN_LIFETIME = timedelta(minutes=15)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
"""


def valid_text(value, limit):
    if not isinstance(value, str) or len(value) > limit or not value.strip():
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def note_response(row):
    return {"id": row["id"], "body_html": str(escape(row["body"]))}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=Path(app.instance_path) / "lab01.sqlite3",
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config is not None:
        app.config.update(test_config)

    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise RuntimeError("Set JWT_SECRET to a value generated from at least 32 random bytes.")

    database = Path(app.config["DATABASE"])
    database.parent.mkdir(parents=True, exist_ok=True)
    hasher = PasswordHasher()
    dummy_hash = hasher.hash(secrets.token_hex(32))

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(database)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript(SCHEMA)

    @app.cli.command("create-user")
    @click.argument("username")
    def create_user(username):
        if not valid_text(username, 64):
            raise click.ClickException("Enter a username of 1 to 64 characters.")
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        if not valid_text(password, 256):
            raise click.ClickException("Enter a password of 1 to 256 characters.")
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hasher.hash(password)),
                )
        except sqlite3.IntegrityError as error:
            raise click.ClickException("Username already exists.") from error
        click.echo("User created.")

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(413)
    def body_too_large(_error):
        return jsonify(error="Request body is too large"), 413

    def unauthorized():
        return jsonify(error="Invalid or missing token"), 401, {"WWW-Authenticate": AUTH_SCHEME}

    def require_token(view):
        @wraps(view)
        def authenticated_view(*args, **kwargs):
            scheme, _, token = request.headers.get("Authorization", "").partition(" ")
            if scheme.lower() != AUTH_SCHEME.lower() or not token:
                return unauthorized()
            try:
                claims = jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    audience=AUDIENCE,
                    issuer=ISSUER,
                    options={"require": ["sub", "iat", "exp", "iss", "aud"]},
                )
            except jwt.InvalidTokenError:
                return unauthorized()
            user = db().execute("SELECT id FROM users WHERE id = ?", (claims["sub"],)).fetchone()
            if user is None or str(user["id"]) != claims["sub"]:
                return unauthorized()
            g.user_id = user["id"]
            return view(*args, **kwargs)

        return authenticated_view

    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
            return jsonify(error="Provide a username and password"), 400
        username, password = payload["username"], payload["password"]
        if not valid_text(username, 64) or not valid_text(password, 256):
            return jsonify(error="Provide a valid username and password"), 400

        user = db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        try:
            hasher.verify(user["password_hash"] if user else dummy_hash, password)
        except (VerificationError, InvalidHashError):
            return jsonify(error="Invalid credentials"), 401
        if user is None:
            return jsonify(error="Invalid credentials"), 401

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(user["id"]),
                "iat": now,
                "exp": now + TOKEN_LIFETIME,
                "iss": ISSUER,
                "aud": AUDIENCE,
            },
            secret,
            algorithm="HS256",
        )
        response = jsonify({
            "access_token": token,
            "token_type": AUTH_SCHEME,
            "expires_in": int(TOKEN_LIFETIME.total_seconds()),
        })
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/data")
    @require_token
    def list_notes():
        rows = db().execute(
            "SELECT id, body FROM notes WHERE user_id = ? ORDER BY id",
            (g.user_id,),
        ).fetchall()
        return jsonify(items=[note_response(row) for row in rows])

    @app.post("/api/data")
    @require_token
    def create_note():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"body"}:
            return jsonify(error="Provide a note body"), 400
        body = payload["body"]
        if not valid_text(body, 1000):
            return jsonify(error="Provide a note of 1 to 1000 characters"), 400
        with db() as connection:
            row_id = connection.execute(
                "INSERT INTO notes (user_id, body) VALUES (?, ?)",
                (g.user_id, body),
            ).lastrowid
        return jsonify(note_response({"id": row_id, "body": body})), 201

    return app
