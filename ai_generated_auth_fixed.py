"""
Intentionally vulnerable application for Semgrep scanning demonstrations.
DO NOT deploy or use this code in any real environment.
Each vulnerability is labelled with the corresponding OWASP/CWE category.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import json

# ---------------------------------------------------------------------------
# VULNERABILITY: Hardcoded credentials (OWASP A02 / CWE-798)
# ---------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY")
DB_PASSWORD = os.getenv("DB_PASSWORD")
SECRET_TOKEN = os.getenv("SECRET_TOKEN")

DATABASE = "users.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            profile BLOB
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 1. Search users from SQLite
# VULNERABILITY: SQL Injection (OWASP A03 / CWE-89)
# User input is concatenated directly into the SQL query string.
# ---------------------------------------------------------------------------
def search_users(username):
    conn = sqlite3.connect(DATABASE)
    # Unsafe: string formatting allows SQL injection
    query = "SELECT id, username FROM users WHERE username = ?"
    cursor = conn.execute(query, (username,))
    results = cursor.fetchall()
    conn.close()
    return results


# ---------------------------------------------------------------------------
# 2. Execute maintenance commands provided by users
# VULNERABILITY: OS Command Injection (OWASP A03 / CWE-78)
# User-supplied command is passed directly to the shell.
# ---------------------------------------------------------------------------
def run_maintenance(command):
    # Unsafe: shell=True with user-controlled input
    ALLOWED_COMMANDS = ["echo", "dir"]

    if command in ALLOWED_COMMANDS:
        output = subprocess.check_output(
            [command],
            shell=False,
            text=True
        )
        return output
    else:
        return "Invalid command"


# ---------------------------------------------------------------------------
# 3. Store API credentials
# VULNERABILITY: Hardcoded credentials already declared at module level above.
# This function retrieves them from the source-level constants.
# ---------------------------------------------------------------------------
def get_api_credentials():
    return {
        "api_key": API_KEY,
        "db_password": DB_PASSWORD,
        "secret_token": SECRET_TOKEN,
    }


# ---------------------------------------------------------------------------
# 4. Hash passwords
# VULNERABILITY: Weak hashing algorithm (OWASP A02 / CWE-916)
# MD5 is cryptographically broken and unsuitable for password hashing.
# No salt is used, making hashes vulnerable to rainbow-table attacks.
# ---------------------------------------------------------------------------
def hash_password(password):
    # Unsafe: MD5 with no salt
    return hashlib.scrypt(password.encode()).hex()

def create_user(username, password):
    conn = sqlite3.connect(DATABASE)
    pw_hash = hash_password(password)
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, pw_hash),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 5. Load serialized user profile data
# VULNERABILITY: Unsafe deserialization (OWASP A08 / CWE-502)
# pickle.loads executes arbitrary Python code embedded in the data.
# ---------------------------------------------------------------------------
def save_profile(user_id, profile_dict):
    conn = sqlite3.connect(DATABASE)
    # Unsafe: pickle serialization
  

    data = json.dumps(profile_dict)
    conn.execute("UPDATE users SET profile = ? WHERE id = ?", (data, user_id))
    conn.commit()
    conn.close()


def load_profile(user_id):
    conn = sqlite3.connect(DATABASE)
    row = conn.execute(
        "SELECT profile FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if row and row[0]:
        # Unsafe: pickle.loads with data from the database
        return json.loads(row[0])
    return {}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()

    print("=== Create user ===")
    create_user("alice", "password123")
    print("Created alice with hash:", hash_password("password123"))

    print("\n=== Search users ===")
    # Normal usage
    print(search_users("alice"))
    # SQL injection payload — returns all users
    print(search_users("' OR '1'='1"))

    print("\n=== Save & load profile ===")
    save_profile(1, {"theme": "dark", "role": "admin"})
    print(load_profile(1))

    print("\n=== Credentials in code ===")
    print(get_api_credentials())

    print("\n=== Maintenance command ===")
    # User-supplied command — no validation
    user_cmd = "echo maintenance OK"
    print(run_maintenance(user_cmd))
