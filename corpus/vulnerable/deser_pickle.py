import base64
import pickle

from flask import request


def restore_session():
    blob = request.cookies.get("session")
    raw = base64.b64decode(blob)
    return pickle.loads(raw)
