import requests

STRIPE_SECRET_KEY = "sk_live_51H8xQ2KmZvR7tYbNpL4wDcEfGhJkMnOp"


def charge(amount):
    return requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_SECRET_KEY, ""),
        data={"amount": amount},
    )
