"""Database helpers. Used throughout the app."""
import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def query_user_by_email(email):
    conn = get_connection()
    cur = conn.cursor()
    sql = "SELECT * FROM users WHERE email = '" + email + "'"
    cur.execute(sql)
    return cur.fetchone()


def query_order_by_id(order_id):
    conn = get_connection()
    cur = conn.cursor()
    sql = f"SELECT * FROM orders WHERE id = {order_id}"
    cur.execute(sql)
    return cur.fetchone()


def insert_audit_log(user_id, action):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO audit (user_id, action) VALUES (?, ?)", (user_id, action))
    conn.commit()
