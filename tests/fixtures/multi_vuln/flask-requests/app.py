from flask import Flask, session
import requests

app = Flask(__name__)
app.secret_key = "eval-fixture-secret-key"


@app.route("/login")
def login():
    session.permanent = True
    requests.get("https://example.com", proxies=None)
    return "logged in"
