import jsonpickle

from flask import request


def revive():
    state = request.form.get("state")
    return jsonpickle.decode(state)
