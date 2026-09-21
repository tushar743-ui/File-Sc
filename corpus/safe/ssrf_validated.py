import requests

from flask import request


def validate_url(candidate):
    if not candidate.startswith("https://api.internal/"):
        raise ValueError("bad url")
    return candidate


def call_api():
    url = validate_url(request.args.get("url"))
    return requests.get(url, timeout=5).json()
