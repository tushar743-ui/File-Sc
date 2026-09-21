import os

from flask import request


def rotate():
    targets = request.form.getlist("targets")
    command = ""
    for target in targets:
        command = command + " " + target
    command = "logrotate -f /etc/logrotate.conf"
    os.system(command)
