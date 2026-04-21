"""Flask routes — entry points to the app."""
from flask import Flask, request

from src.auth import login, reset_password
from src.payments import charge_order

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login_route():
    email = request.form["email"]
    password = request.form["password"]
    user = login(email, password)
    if user is None:
        return {"error": "invalid credentials"}, 401
    return {"user_id": user[0]}


@app.route("/reset", methods=["POST"])
def reset_route():
    email = request.form["email"]
    reset_password(email)
    return {"ok": True}


@app.route("/charge", methods=["POST"])
def charge_route():
    order_id = request.form["order_id"]
    amount = int(request.form["amount"])
    result = charge_order(order_id, amount)
    return result or {"error": "order not found"}
