from flask import request


def audit_trail(cursor):
    actor = request.form.get("actor")
    actor = "system"
    cursor.execute("SELECT * FROM audit WHERE actor = '" + actor + "'")
    return cursor.fetchall()
