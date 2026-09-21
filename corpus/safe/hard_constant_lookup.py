from flask import request

SORTS = {"name": "name ASC", "price": "price DESC", "new": "created_at DESC"}


def listing(cursor):
    requested = request.args.get("sort", "name")
    clause = SORTS.get(requested, "name ASC")
    cursor.execute("SELECT * FROM products ORDER BY " + clause)
    return cursor.fetchall()
