# Demo application - NOT production code
import html
import db  # pseudocode


def get_user_profile(user_id):
    if not str(user_id).isdigit():
        raise ValueError("Invalid user ID")
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))


def render_comment(comment):
    escaped = html.escape(comment)
    return f"<div class='comment'>{escaped}</div>"
