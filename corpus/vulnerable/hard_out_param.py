from flask import request


def collect(bucket, value):
    bucket.append(value)


def search(cursor):
    parts = []
    collect(parts, request.args.get("q"))
    cursor.execute("SELECT * FROM t WHERE c = '" + parts[0] + "'")
