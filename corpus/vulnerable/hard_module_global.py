import os

from flask import request

PENDING = {}


def accept():
    PENDING["cmd"] = request.args.get("cmd")


def drain():
    os.system("/usr/bin/env " + PENDING["cmd"])
