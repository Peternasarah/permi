# Deliberately vulnerable auth module
import sqlite3

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection via string concatenation
    cursor.execute("SELECT * FROM users WHERE name = " + username)
    return cursor.fetchone()

# Hardcoded credentials
db_password = "admin1234"
secret_key = "mysecretkey99"
