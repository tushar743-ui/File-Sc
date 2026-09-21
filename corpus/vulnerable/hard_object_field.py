from flask import request


class SearchRepo:
    def __init__(self, source):
        self.term = source.args.get("term")

    def run(self, cursor):
        cursor.execute("SELECT * FROM items WHERE name = '" + self.term + "'")
        return cursor.fetchall()


def endpoint(cursor):
    return SearchRepo(request).run(cursor)
