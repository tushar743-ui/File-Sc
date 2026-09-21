import yaml

from flask import request


def load_config():
    body = request.data
    return yaml.load(body, Loader=yaml.SafeLoader)
