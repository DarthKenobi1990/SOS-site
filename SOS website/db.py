import sqlite3
import bcrypt

def create_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def register_user(username, email, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone():
        print("Username or email already exists.")
        conn.close()
        return False
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
    conn.commit()
    conn.close()
    print("User registered successfully.")
    return True

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    record = cursor.fetchone()
    
    if record and bcrypt.checkpw(password.encode('utf-8'), record[0]):
        print("Login successful!")
        conn.close()
        return True
    else:
        print("Invalid username or password.")
        conn.close()
        return False

if __name__ == "__main__":
    create_database()
    while True:
        action = input("Choose action: register (r) / login (l) / exit (e): ").strip().lower()
        if action == 'r':
            user = input("Enter username: ")
            email = input("Enter email: ")
            pwd = input("Enter password: ")
            register_user(user, email, pwd)
        elif action == 'l':
            user = input("Enter username: ")
            pwd = input("Enter password: ")
            login_user(user, pwd)
        elif action == 'e':
            break
        else:
            print("Invalid option. Try again.")
