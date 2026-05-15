def get_user_by_id(conn, user_id):
    # Параметризованный запрос — драйвер сам экранирует значение.
    query = "SELECT id, email FROM users WHERE id = ?"
    row = conn.execute(query, (user_id,)).fetchone()
    return row
