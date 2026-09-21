import os

from werkzeug.utils import secure_filename


def join_upload(root, name):
    return os.path.join(root, name)


def safe_upload(root, name):
    return os.path.join(root, secure_filename(name))


def read_file(path):
    with open(path) as handle:
        return handle.read()
