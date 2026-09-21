import os

from flask import request


def batch():
    names = request.form.getlist("names")
    command = "rm -f"
    for name in names:
        command = command + " " + name
    os.system(command)
