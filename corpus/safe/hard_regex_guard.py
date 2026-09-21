import os
import re

from flask import request

HOSTNAME = re.compile(r"\A[a-z0-9.-]{1,253}\Z")


def ping():
    host = request.args.get("host", "")
    if not HOSTNAME.fullmatch(host):
        raise ValueError("invalid hostname")
    os.system("ping -c 1 " + host)
