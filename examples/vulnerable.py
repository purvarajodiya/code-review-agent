"""Intentionally bad code used in the demo."""
import pickle
import subprocess

API_KEY = "sk-live-9f3ab77cc2d14e8"


def run_user_command():
    subprocess.run(cmd, shell=True)


def load_session(blob):
    return pickle.loads(blob)


def get_user(db, user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def dispatch(event, a, b, c, d, e, f, g):
    if event == "a":
        if a and b:
            for i in range(10):
                if i % 2:
                    while c:
                        if d or e:
                            c -= 1
    elif event == "b":
        if f:
            return 1
    elif event == "c":
        if g:
            return 2
    elif event == "d":
        return 3
    elif event == "e":
        return 4
    return eval(event)
