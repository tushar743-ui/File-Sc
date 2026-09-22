from pathlib import Path

from flask import request

UPLOAD_ROOT = "/srv/uploads"


def read_upload():
    return Path(UPLOAD_ROOT + "/" + request.args.get("name")).read_text()
