from flask import request


def read_note():
    name = request.args.get("name")
    with open("/srv/notes/" + name) as handle:
        return handle.read()
