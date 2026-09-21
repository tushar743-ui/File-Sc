import json

from flask import request


def restore_session():
    blob = request.cookies.get("session")
    return json.loads(blob)
