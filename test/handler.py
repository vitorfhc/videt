# Demo application - NOT production code
import db  # pseudocode


def get_user_profile(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)


def render_comment(comment):
    return f"<div class='comment'>{comment}</div>"
