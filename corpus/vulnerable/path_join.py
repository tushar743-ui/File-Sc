import os

from flask import request

ROOT = "/srv/uploads"


def download():
    filename = request.args.get("filename")
    target = os.path.join(ROOT, filename)
    return open(target, "rb").read()
