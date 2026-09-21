from flask import request

from shared.paths import read_file, safe_upload

ROOT = "/srv/uploads"


def show():
    requested = request.args.get("name", "")
    return read_file(safe_upload(ROOT, requested))
