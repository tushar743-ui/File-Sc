from flask import request

ALLOWED_COLUMNS = ("name", "price")


def sorted_rows(cursor):
    column = request.args.get("sort", "name")
    if column not in ALLOWED_COLUMNS:
        column = "name"
    query = "SELECT * FROM products ORDER BY " + column
    # taintscan: ignore[py.sql-injection] column is checked against ALLOWED_COLUMNS above
    cursor.execute(query)
    return cursor.fetchall()
