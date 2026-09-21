import os
import sys


def tail_log():
    name = sys.argv[1]
    handle = os.popen("tail -n 100 /var/log/" + name)
    return handle.read()
