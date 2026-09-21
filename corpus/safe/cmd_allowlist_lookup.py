import subprocess

from flask import request

TASKS = {"backup": "/usr/local/bin/backup.sh", "report": "/usr/local/bin/report.sh"}


def run_task():
    name = request.form.get("task")
    if name not in TASKS:
        raise ValueError("unknown task")
    subprocess.run([TASKS["backup"]], check=True)
