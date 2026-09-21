import os

from flask import request

ROOT = "/srv/uploads"


def download():
    name = request.args.get("name", "")
    full = os.path.abspath(os.path.join(ROOT, name))
    if not full.startswith(ROOT + os.sep):
        raise ValueError("outside root")
    return open(full, "rb").read()
