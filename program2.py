import sqlite3

def execute_query(username, password):
    # This query is vulnerable to SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor = sqlite3.connect('my_database.db').cursor()
    cursor.execute(query)
    return cursor.fetchall()