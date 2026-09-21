import os

from flask import request


class BaseRunner:
    def execute_now(self, command):
        os.system(command)


class Runner(BaseRunner):
    pass


def go():
    Runner().execute_now(request.args.get("cmd"))
