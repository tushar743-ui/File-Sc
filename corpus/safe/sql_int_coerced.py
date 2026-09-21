from flask import request


def order_by_id(cursor):
    order_id = int(request.args.get("order_id", "0"))
    cursor.execute("SELECT * FROM orders WHERE id = %d" % order_id)
    return cursor.fetchall()
