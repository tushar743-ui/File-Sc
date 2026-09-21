from flask import request


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def page(cursor):
    offset = as_int(request.args.get("page"))
    cursor.execute("SELECT * FROM t LIMIT 20 OFFSET %d" % offset)
    return cursor.fetchall()
