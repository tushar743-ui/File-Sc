from flask import request


def delete_order(conn):
    order_id = request.args.get("order_id")
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM orders WHERE id = %(id)s", {"id": order_id})
