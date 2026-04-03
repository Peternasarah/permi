# test_vuln.py — deliberately vulnerable code for testing
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + username)  # SQL001
    return cursor.fetchall()

password = "supersecret123"   # SEC001
DEBUG = True                  # INS001 — wait, this won't match, let's fix:
debug = True                  # INS001
