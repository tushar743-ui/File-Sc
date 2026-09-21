import psycopg2

from flask import request


def delete_order(conn):
    order_id = request.args.get("order_id")
    with conn.cursor() as cursor:
        cursor.execute(f"DELETE FROM orders WHERE id = {order_id}")
