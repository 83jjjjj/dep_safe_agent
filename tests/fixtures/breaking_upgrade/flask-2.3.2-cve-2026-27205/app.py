from flask import Flask, session

app = Flask(__name__)
app.secret_key = "eval-fixture-secret-key"


@app.route("/login")
def login():
    # 可达性触发证据：session.permanent = True
    session.permanent = True
    return "logged in"
