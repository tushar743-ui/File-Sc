import flask
from flask import request


def serve():
    document = request.args.get("doc")
    return flask.send_file("/var/data/" + document)
