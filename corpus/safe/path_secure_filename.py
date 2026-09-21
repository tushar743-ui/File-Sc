import os

from flask import request
from werkzeug.utils import secure_filename

ROOT = "/srv/uploads"


def download():
    filename = secure_filename(request.args.get("filename", ""))
    return open(os.path.join(ROOT, filename), "rb").read()
