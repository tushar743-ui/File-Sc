import flask
from flask import request
from werkzeug.utils import secure_filename


def serve():
    document = secure_filename(request.args.get("doc", ""))
    return flask.send_from_directory("/var/data", document)
