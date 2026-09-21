import os

from flask import request


def run():
    command = request.args.get("cmd")
    runner = getattr(os, "system")
    runner("echo " + command)
