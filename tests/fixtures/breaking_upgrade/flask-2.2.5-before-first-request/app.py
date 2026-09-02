from flask import Flask, session

app = Flask(__name__)
app.secret_key = "eval-fixture-secret-key"


@app.before_first_request
def init_state():
    # flask 3.0 移除了 before_first_request → 跨大版本修复后此代码必然崩溃
    session.permanent = True


@app.route("/login")
def login():
    return "logged in"
