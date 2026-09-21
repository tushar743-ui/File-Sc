from flask import request


TEMPLATE = "SELECT * FROM audit WHERE actor = '{}' ORDER BY created_at"


def audit_trail(cursor):
    actor = request.form.get("actor")
    cursor.execute(TEMPLATE.format(actor))
    return cursor.fetchall()
