import os

from flask import request


def read_note():
    name = os.path.basename(request.args.get("name", ""))
    with open("/srv/notes/" + name) as handle:
        return handle.read()
