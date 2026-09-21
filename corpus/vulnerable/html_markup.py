from flask import request
from markupsafe import Markup


def banner():
    message = request.args.get("message")
    return Markup("<div class='banner'>" + message + "</div>")
