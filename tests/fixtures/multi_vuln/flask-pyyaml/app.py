from flask import Flask, session
import yaml

app = Flask(__name__)
app.secret_key = "eval-fixture-secret-key"


@app.route("/login")
def login():
    # flask 触发证据：session.permanent = True
    session.permanent = True
    # pyyaml 触发证据：yaml.load 不安全加载
    yaml.load("key: value")
    return "logged in"
