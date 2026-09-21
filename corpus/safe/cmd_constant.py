import os

from flask import request


def rotate_logs():
    _requested = request.args.get("which")
    os.system("logrotate -f /etc/logrotate.conf")
