from flask import request

QUERY = "SELECT id, name FROM products WHERE active = 1"


def active_products(cursor):
    _unused = request.args.get("page")
    cursor.execute(QUERY)
    return cursor.fetchall()
