from flask import make_response, request


def show_comment():
    return make_response("<p>" + request.form.get("comment") + "</p>")
