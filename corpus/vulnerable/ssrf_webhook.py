import httpx

from flask import request


def register_webhook():
    payload = request.get_json()
    endpoint = payload["callback"]
    return httpx.post(endpoint, json={"ok": True}).status_code
