import requests

from flask import request

ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}


def fetch_preview():
    host = request.args.get("host")
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get("https://images.example.com/preview", timeout=5).text
