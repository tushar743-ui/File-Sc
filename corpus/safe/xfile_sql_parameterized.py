from flask import request

from shared.dbhelpers import run_parameterized


def report(cursor):
    actor = request.args.get("actor")
    return run_parameterized(cursor, "SELECT * FROM audit WHERE actor = %s", (actor,))
