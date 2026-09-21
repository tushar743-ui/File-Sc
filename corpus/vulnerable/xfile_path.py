from flask import request

from shared.paths import join_upload, read_file


def show():
    name = request.args.get("name")
    return read_file(join_upload("/srv/uploads", name))
