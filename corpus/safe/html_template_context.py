from flask import render_template, request


def greet():
    name = request.args.get("name")
    return render_template("greet.html", name=name)
