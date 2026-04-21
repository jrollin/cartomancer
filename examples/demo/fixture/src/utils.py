"""Misc helpers. Not called from anywhere in the app."""
import pickle


def load_cache(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def format_amount(cents):
    return f"${cents / 100:.2f}"
