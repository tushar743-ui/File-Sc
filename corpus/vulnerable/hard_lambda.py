from flask import request
from markupsafe import Markup


def banner():
    message = request.args.get("message")
    wrap = lambda value: Markup("<div>" + value + "</div>")
    return wrap(message)
