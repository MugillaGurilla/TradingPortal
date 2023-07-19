# This file is for utility, frequently used, but short functions

from datetime import datetime

def get_username(db, session):
    user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    return user

def get_now():
    current_datetime = datetime.now()
    now = current_datetime.strftime("%Y-%m-%d %H:%M")
    return now

def get_user_id(db, username):
    id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
    return id
