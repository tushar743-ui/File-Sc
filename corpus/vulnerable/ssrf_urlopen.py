import urllib.request

from flask import request


def proxy():
    target = request.args.get("target")
    with urllib.request.urlopen("http://" + target) as response:
        return response.read()
