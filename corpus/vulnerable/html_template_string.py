from flask import render_template_string, request


def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")
