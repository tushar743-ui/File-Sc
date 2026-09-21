import os

from flask import request


def purge():
    key = request.form["key"]
    os.remove(os.path.join("/tmp/cache", key))
