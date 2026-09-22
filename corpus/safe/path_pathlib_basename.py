import os
from pathlib import Path

from flask import request

UPLOAD_ROOT = "/srv/uploads"


def read_upload():
    name = os.path.basename(request.args.get("name", ""))
    return Path(UPLOAD_ROOT + "/" + name).read_text()
