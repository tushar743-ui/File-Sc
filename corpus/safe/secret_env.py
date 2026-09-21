import os

STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")


def configured():
    return bool(STRIPE_SECRET_KEY and DB_PASSWORD)
