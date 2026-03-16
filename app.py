FIXED APP.PY (No dotenv dependency)

from flask import Flask, request, redirect, session import sqlite3 from
datetime import datetime, timedelta

app = Flask(name) app.secret_key = “lucidmage_secret_change_this”

DB_NAME = “touchpoints.db”

def get_db(): conn = sqlite3.connect(DB_NAME) conn.row_factory =
sqlite3.Row return conn

def init_db(): conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'client'
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS touchpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client TEXT NOT NULL,
        comments INTEGER NOT NULL DEFAULT 0,
        dms INTEGER NOT NULL DEFAULT 0,
        reactions INTEGER NOT NULL DEFAULT 0,
        friends INTEGER NOT NULL DEFAULT 0,
        posts INTEGER NOT NULL DEFAULT 0,
        notes TEXT DEFAULT '',
        date TEXT NOT NULL
    )
    """)

    conn.commit()

    existing_admin = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        ("jeff",)
    ).fetchone()

    if not existing_admin:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("jeff", "lucidmage", "admin")
        )
        conn.commit()

    conn.close()

init_db()

@app.route(“/”) def home(): return “Lucid Mage Touchpoint Tracker
Running”

if name == “main”: app.run(host=“0.0.0.0”, port=10000)
