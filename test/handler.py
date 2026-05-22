# Demo application - NOT production code
import html
import os
import db  # pseudocode


def get_user_profile(user_id):
    if not str(user_id).isdigit():
        raise ValueError("Invalid user ID")
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))


def render_comment(comment):
    escaped = html.escape(comment)
    return f"<div class='comment'>{escaped}</div>"


def get_file(path):
    base = "/var/app/files"
    safe_path = os.path.realpath(os.path.join(base, path))
    if not safe_path.startswith(base):
        raise ValueError("Path traversal detected")
    with open(safe_path) as f:
        return f.read()
