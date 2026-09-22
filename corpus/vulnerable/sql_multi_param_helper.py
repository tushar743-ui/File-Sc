from flask import request


def query(cursor, table, term):
    cursor.execute("SELECT * FROM " + table + " WHERE name = '" + term + "'")


def handler(cursor):
    query(cursor, "reports", request.args.get("q"))
