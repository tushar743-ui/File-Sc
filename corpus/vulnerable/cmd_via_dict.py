import subprocess

from flask import request


def run_task():
    options = {"cmd": request.json["command"]}
    subprocess.check_output("/usr/bin/env " + options["cmd"], shell=True)
