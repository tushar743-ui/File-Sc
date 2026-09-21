import subprocess

from flask import request


class BaseRunner:
    def execute_now(self, command):
        subprocess.run(["echo", command], shell=False, check=False)


class Runner(BaseRunner):
    pass


def go():
    Runner().execute_now(request.args.get("cmd"))
