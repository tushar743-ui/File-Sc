import requests

from flask import request


def fetch_preview():
    url = request.args.get("url")
    response = requests.get(url, timeout=5)
    return response.text
