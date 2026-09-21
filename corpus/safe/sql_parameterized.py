import sqlite3

from flask import request


def lookup_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
