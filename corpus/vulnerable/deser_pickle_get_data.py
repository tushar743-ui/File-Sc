import pickle

from flask import request


def load_state():
    return pickle.loads(request.get_data())
