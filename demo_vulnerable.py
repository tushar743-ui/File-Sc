import base64
import hashlib
import hmac
import json
import logging
import os
import pickle
import random
import shelve
import sqlite3
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import jinja2
import requests
import yaml
from flask import Flask, Markup, make_response, redirect, render_template_string, request
from markupsafe import escape

app = Flask(__name__)
log = logging.getLogger(__name__)

DB = sqlite3.connect("app.db", check_same_thread=False)
UPLOAD_ROOT = "/srv/uploads"
ALLOWED_COLUMNS = ("id", "name", "email")

STRIPE_SECRET_KEY = "sk_live_51H8xQ2KmZvR7tYbNpQwErTyUiOpAsDfGhJkL"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "P@ssw0rd!ProdCluster2024"
JWT_SIGNING_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9SUPERSECRET"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
VAULT_TOKEN = "s.FnL7qg0YnHZDpf4zKKuFy0UK"
PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"

API_ENDPOINT = "https://api.example.com/v1"
DEFAULT_TIMEOUT = 30
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


@app.route("/sql/concat")
def sqli_string_concat():
    name = request.args.get("name")
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return json.dumps(cursor.fetchall())


@app.route("/sql/percent")
def sqli_percent_format():
    uid = request.args.get("id")
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)
    return json.dumps(cursor.fetchall())


@app.route("/sql/format")
def sqli_str_format():
    table = request.form.get("table")
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM {}".format(table))
    return json.dumps(cursor.fetchall())


@app.route("/sql/fstring")
def sqli_fstring():
    order = request.args.get("order")
    cursor = DB.cursor()
    cursor.execute(f"SELECT * FROM users ORDER BY {order}")
    return json.dumps(cursor.fetchall())


@app.route("/sql/script")
def sqli_executescript():
    payload = request.get_json().get("sql")
    DB.cursor().executescript("BEGIN; " + payload + " COMMIT;")
    return "ok"


@app.route("/sql/env")
def sqli_from_environment():
    tenant = os.environ.get("TENANT_SCHEMA")
    DB.cursor().execute("SET search_path TO " + tenant)
    return "ok"


@app.route("/cmd/system")
def cmdi_os_system():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/cmd/popen")
def cmdi_os_popen():
    target = request.args.get("target")
    return os.popen("nslookup " + target).read()


@app.route("/cmd/shell-true")
def cmdi_subprocess_shell():
    archive = request.args.get("archive")
    subprocess.run("tar xzf " + archive, shell=True, check=False)
    return "ok"


@app.route("/cmd/check-output")
def cmdi_check_output():
    branch = request.form.get("branch")
    return subprocess.check_output(f"git log {branch}", shell=True).decode()


@app.route("/cmd/execl")
def cmdi_os_exec():
    binary = request.args.get("bin")
    os.execl("/bin/sh", "sh", "-c", binary)


@app.route("/cmd/getattr")
def cmdi_getattr_dispatch():
    command = request.args.get("cmd")
    runner = getattr(os, "system")
    runner("echo " + command)
    return "ok"


@app.route("/cmd/lambda")
def cmdi_through_lambda():
    command = request.args.get("cmd")
    run = lambda value: os.system("sh -c " + value)
    return str(run(command))


@app.route("/path/open")
def path_traversal_open():
    name = request.args.get("name")
    with open(os.path.join(UPLOAD_ROOT, name)) as handle:
        return handle.read()


@app.route("/path/read-text")
def path_traversal_pathlib():
    name = request.args.get("name")
    return Path(UPLOAD_ROOT + "/" + name).read_text()


@app.route("/path/remove")
def path_traversal_delete():
    name = request.args.get("name")
    os.remove(UPLOAD_ROOT + "/" + name)
    return "deleted"


@app.route("/path/zip")
def path_traversal_zip_slip():
    upload = request.files["archive"]
    with zipfile.ZipFile(upload) as bundle:
        bundle.extractall(UPLOAD_ROOT)
    return "extracted"


@app.route("/path/tar")
def path_traversal_tar_slip():
    name = request.args.get("name")
    with tarfile.open(os.path.join(UPLOAD_ROOT, name)) as bundle:
        bundle.extractall("/tmp/unpacked")
    return "extracted"


@app.route("/ssrf/requests")
def ssrf_requests_get():
    url = request.args.get("url")
    return requests.get(url, timeout=DEFAULT_TIMEOUT).text


@app.route("/ssrf/post")
def ssrf_requests_post():
    endpoint = request.form.get("callback")
    return str(requests.post(endpoint, json={"ping": True}).status_code)


@app.route("/ssrf/urlopen")
def ssrf_urlopen():
    from urllib.request import urlopen

    target = request.args.get("target")
    with urlopen(target) as response:
        return response.read().decode()


@app.route("/ssrf/proxy")
def ssrf_via_helper():
    return fetch_remote(request.args.get("url"))


def fetch_remote(location):
    return requests.get(location, timeout=DEFAULT_TIMEOUT).text


@app.route("/html/markup")
def xss_markup():
    message = request.args.get("message")
    return Markup("<div class='banner'>" + message + "</div>")


@app.route("/html/response")
def xss_raw_response():
    comment = request.form.get("comment")
    response = make_response("<p>" + comment + "</p>")
    response.headers["Content-Type"] = "text/html"
    return response


@app.route("/html/template-string")
def ssti_render_template_string():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/html/jinja")
def ssti_jinja_from_string():
    body = request.form.get("template")
    return jinja2.Template(body).render(user="guest")


@app.route("/deser/pickle")
def deserialization_pickle():
    blob = request.get_data()
    return str(pickle.loads(blob))


@app.route("/deser/pickle-b64")
def deserialization_pickle_base64():
    token = request.args.get("state")
    return str(pickle.loads(base64.b64decode(token)))


@app.route("/deser/yaml")
def deserialization_yaml_unsafe():
    document = request.get_data()
    return str(yaml.load(document))


@app.route("/deser/yaml-full")
def deserialization_yaml_full_loader():
    document = request.get_data()
    return str(yaml.load(document, Loader=yaml.FullLoader))


@app.route("/deser/shelve")
def deserialization_shelve():
    name = request.args.get("db")
    with shelve.open(os.path.join(UPLOAD_ROOT, name)) as store:
        return str(dict(store))


@app.route("/eval/expr")
def code_injection_eval():
    expression = request.args.get("expr")
    return str(eval(expression))


@app.route("/eval/exec")
def code_injection_exec():
    snippet = request.form.get("code")
    exec(snippet)
    return "ok"


@app.route("/eval/compile")
def code_injection_compile():
    snippet = request.args.get("src")
    return str(eval(compile(snippet, "<user>", "eval")))


@app.route("/eval/import")
def code_injection_import():
    module = request.args.get("module")
    return str(__import__(module))


@app.route("/xxe")
def xxe_entity_expansion():
    document = request.get_data()
    root = ET.fromstring(document)
    return str(root.tag)


@app.route("/redirect")
def open_redirect():
    destination = request.args.get("next")
    return redirect(destination)


@app.route("/crypto/md5")
def weak_hash_md5():
    password = request.form.get("password")
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/crypto/sha1")
def weak_hash_sha1():
    token = request.args.get("token")
    return hashlib.sha1(token.encode()).hexdigest()


@app.route("/crypto/compare")
def timing_unsafe_comparison():
    supplied = request.headers.get("X-Api-Key")
    return "ok" if supplied == STRIPE_SECRET_KEY else "denied"


@app.route("/crypto/random")
def insecure_random_token():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


@app.route("/crypto/hmac")
def hardcoded_hmac_key():
    body = request.get_data()
    return hmac.new(b"static-signing-key-2024", body, hashlib.sha256).hexdigest()


@app.route("/tempfile")
def insecure_temp_file():
    name = request.args.get("name")
    path = tempfile.mktemp(suffix=name)
    with open(path, "w") as handle:
        handle.write("scratch")
    return path


@app.route("/log")
def log_injection():
    username = request.args.get("user")
    log.info("login attempt for " + username)
    return "ok"


@app.route("/chain/helper")
def sqli_through_helper():
    term = request.args.get("q")
    return run_query(DB.cursor(), build_filter("name", term))


def build_filter(column, value):
    return "SELECT * FROM users WHERE %s = '%s'" % (column, value)


def run_query(cursor, sql):
    cursor.execute(sql)
    return str(cursor.fetchall())


@app.route("/chain/mutation")
def sqli_through_mutated_argument():
    parts = []
    collect(parts, request.args.get("clause"))
    DB.cursor().execute("SELECT * FROM audit WHERE " + parts[0])
    return "ok"


def collect(bucket, value):
    bucket.append(value)


class ReportRepository:
    def __init__(self, source):
        self.term = source.args.get("term")
        self.table = "reports"

    def run(self, cursor):
        cursor.execute("SELECT * FROM " + self.table + " WHERE title = '" + self.term + "'")
        return cursor.fetchall()


@app.route("/chain/constructor")
def sqli_through_constructor():
    return str(ReportRepository(request).run(DB.cursor()))


class BaseExecutor:
    def execute_now(self, command):
        os.system(command)


class TaskExecutor(BaseExecutor):
    pass


@app.route("/chain/inheritance")
def cmdi_through_inherited_method():
    TaskExecutor().execute_now(request.args.get("cmd"))
    return "ok"


@app.route("/chain/dispatch")
def cmdi_through_dispatch_table():
    handlers = {"shell": os.system}
    handlers["shell"]("echo " + request.args.get("cmd"))
    return "ok"


@app.route("/chain/branch")
def sqli_through_branch_merge():
    raw = request.args.get("q")
    if request.args.get("upper"):
        clause = raw.upper()
    else:
        clause = raw
    DB.cursor().execute("SELECT * FROM notes WHERE body = '" + clause + "'")
    return "ok"


@app.route("/chain/dict")
def sqli_through_container():
    payload = {"where": request.args.get("where")}
    DB.cursor().execute("SELECT * FROM notes WHERE " + payload["where"])
    return "ok"


@app.route("/safe/parameterized")
def safe_parameterized_query():
    name = request.args.get("name")
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return json.dumps(cursor.fetchall())


@app.route("/safe/allowlist")
def safe_allowlisted_column():
    column = request.args.get("column", "")
    if column not in ALLOWED_COLUMNS:
        raise ValueError("unknown column")
    DB.cursor().execute("SELECT " + column + " FROM users")
    return "ok"


@app.route("/safe/argv")
def safe_subprocess_argument_list():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
    return "ok"


@app.route("/safe/basename")
def safe_path_basename():
    name = request.args.get("name")
    with open(os.path.join(UPLOAD_ROOT, os.path.basename(name))) as handle:
        return handle.read()


@app.route("/safe/containment")
def safe_path_containment_check():
    name = request.args.get("name", "")
    full = os.path.abspath(os.path.join(UPLOAD_ROOT, name))
    if not full.startswith(UPLOAD_ROOT + os.sep):
        raise ValueError("outside root")
    with open(full) as handle:
        return handle.read()


@app.route("/safe/escaped")
def safe_escaped_html():
    message = request.args.get("message")
    return Markup("<div>" + escape(message) + "</div>")


@app.route("/safe/yaml")
def safe_yaml_load():
    return str(yaml.safe_load(request.get_data()))


@app.route("/safe/coerced")
def safe_integer_coercion():
    page = int(request.args.get("page", "1"))
    DB.cursor().execute("SELECT * FROM users LIMIT " + str(page))
    return "ok"


@app.route("/safe/reassigned")
def safe_taint_killed_by_reassignment():
    value = request.args.get("value")
    value = "constant"
    os.system("echo " + value)
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
