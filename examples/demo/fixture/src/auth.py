"""Authentication — login and session handling."""
import hashlib

from src.db import query_user_by_email, insert_audit_log


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def login(email, password):
    user = query_user_by_email(email)
    if user is None:
        return None
    if user[2] == hash_password(password):
        insert_audit_log(user[0], "login")
        return user
    return None


def reset_password(email):
    user = query_user_by_email(email)
    if user is None:
        return False
    insert_audit_log(user[0], "password_reset")
    return True
