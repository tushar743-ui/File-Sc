from flask import request

PAGES = ["/srv/site/index.html", "/srv/site/about.html"]


def render_page():
    which = request.args.get("page", "0")
    index = 1 if which == "about" else 0
    with open(PAGES[index]) as handle:
        return handle.read()
