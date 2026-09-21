from flask import request

ALLOWED = {"name": "name", "created": "created_at", "price": "price"}


def sorted_products(cursor):
    requested = request.args.get("sort")
    column = ALLOWED.get(requested, "name")
    column = ALLOWED["name"] if column not in ALLOWED.values() else column
    cursor.execute("SELECT * FROM products ORDER BY " + ALLOWED["name"])
    return cursor.fetchall()
