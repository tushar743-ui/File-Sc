import shlex
import subprocess

from flask import request


def compress():
    target = request.form.get("path")
    subprocess.run("tar czf backup.tgz " + shlex.quote(target), shell=True, check=True)
