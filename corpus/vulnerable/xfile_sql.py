from flask import request

from shared.dbhelpers import run_query


def report(cursor):
    actor = request.args.get("actor")
    return run_query(cursor, "SELECT * FROM audit WHERE actor = '" + actor + "'")
