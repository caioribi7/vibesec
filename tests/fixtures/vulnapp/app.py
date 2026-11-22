# App PROPOSITALMENTE VULNERÁVEL usado nos testes do VibeSec. Não faça deploy.
import hashlib
import os
import pickle
import sqlite3

import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
db.execute("INSERT OR IGNORE INTO users VALUES (1, 'ana')")
db.commit()


@app.route("/")
def index():
    return '<a href="/user?id=1">perfil</a> <a href="/hello?name=visitante">oi</a>'


@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    rows = db.execute(f"SELECT name FROM users WHERE id = {uid}").fetchall()
    return str(rows)


@app.route("/hello")
def hello():
    name = request.args.get("name", "mundo")
    return render_template_string(f"<h1>Olá {name}</h1>")


@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args.get("host", "127.0.0.1"))
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
