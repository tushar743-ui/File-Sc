import html

from flask import request
from markupsafe import Markup


def banner():
    message = html.escape(request.args.get("message", ""))
    return Markup("<div class='banner'>" + message + "</div>")
