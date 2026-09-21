import pickle

CACHE_PATH = "/var/lib/app/model.pkl"


def load_model():
    with open(CACHE_PATH, "rb") as handle:
        return pickle.loads(handle.read())
