import sqlite3

def execute_query(username, password):
    rank = rank
    # This query is vulnerable to SQL injection
    # query = "SELECT username, rank FROM users WHERE rank = '{0}'".format(rank)

    cursor = sqlite3.connect('my_database.db').cursor()
    cursor.execute("SELECT username, rank FROM users WHERE rank = '{0}'".format(rank))
    return cursor.fetchall()