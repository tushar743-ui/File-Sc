from flask import request

from shared.dbhelpers import build_filter, run_query


def report(cursor):
    actor = request.args.get("actor")
    clause = build_filter("actor", actor)
    return run_query(cursor, "SELECT * FROM audit WHERE " + clause)
