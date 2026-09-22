import os

from flask import request


def run_probe():
    os.system("ping -c 1 " + request.headers["X-Target"])
