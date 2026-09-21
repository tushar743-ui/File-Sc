from flask import request

COMMANDS = ("status", "uptime", "df -h")


def run_dashboard():
    import subprocess

    choice = request.args.get("choice", "0")
    index = COMMANDS.index("uptime") if choice == "uptime" else 0
    subprocess.run(COMMANDS[index], shell=True, check=False)
