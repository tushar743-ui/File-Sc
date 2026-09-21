import subprocess

from flask import request


def compress():
    target = request.form.get("path")
    subprocess.run(f"tar czf backup.tgz {target}", shell=True, check=True)
