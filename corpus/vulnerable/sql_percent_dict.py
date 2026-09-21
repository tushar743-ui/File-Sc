from flask import request


def search(cursor):
    filters = {}
    filters["term"] = request.args.get("term")
    statement = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % filters["term"]
    cursor.execute(statement)
    return cursor.fetchall()
