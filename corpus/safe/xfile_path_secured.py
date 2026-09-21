from flask import request

from shared.paths import read_file, safe_upload


def show():
    name = request.args.get("name")
    return read_file(safe_upload("/srv/uploads", name))
