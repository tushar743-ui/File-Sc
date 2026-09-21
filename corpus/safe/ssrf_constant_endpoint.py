import httpx

from flask import request

ENDPOINT = "https://hooks.example.com/notify"


def register_webhook():
    payload = request.get_json()
    return httpx.post(ENDPOINT, json={"id": payload["id"]}).status_code
