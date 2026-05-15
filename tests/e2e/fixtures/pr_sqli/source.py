def get_user_by_id(conn, user_id):
    # NOTE: легитимный bug — user_id уходит в f-string без параметризации.
    query = f"SELECT id, email FROM users WHERE id = {user_id}"
    row = conn.execute(query).fetchone()
    return row
