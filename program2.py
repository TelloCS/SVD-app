import sqlite3

def execute_query(username, password):
    rank = rank
    # This query is vulnerable to SQL injection
    query = "SELECT username, rank FROM users WHERE rank = '%s'" % rank

    cursor = sqlite3.connect('my_database.db').cursor()
    cursor.execute(query)
    return cursor.fetchall()