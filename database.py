import sqlite3
from config import DB_NAME

# Global connection to be used across modules
conn = None

def get_db_connection():
    global conn
    if conn is None:
        # Check SameSite setting for security if using web-server, but not needed for cli tool
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row # Access columns by name
    return conn
# print(user['id'])     # id
# print(user['name'])   # name

def close_db_connection():
    global conn
    if conn:
        conn.close()
        conn = None

def init_db():
    print("Initializing database...")
    conn = get_db_connection()
    try:
        #cursor is the object we use to execute SQL queries
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                is_locked BOOLEAN DEFAULT FALSE,
                last_login_attempt REAL -- Unix timestamp for lockout calculation
            )
        """)
        
        # Create subjects table for storing user subjects
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY,
                student_email TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                assigned_by TEXT NOT NULL,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_email) REFERENCES users(email),
                UNIQUE(student_email, subject_name)
            )
        """)
        conn.commit()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Database initialization error: {e}")
        close_db_connection()

# Call once at the start of the application
init_db()