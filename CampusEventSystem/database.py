import sqlite3
from flask import g

DATABASE = 'event_management.db'

def get_db():
    """Open a connection to the SQLite database."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # This allows access to columns by name
    return g.db

def close_db():
    """Close the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    """Query the database and return the result."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allows column access by name
    cursor = conn.cursor()
    cursor.execute(query, args)
    result = cursor.fetchall()
    conn.close()
    return (result[0] if result else None) if one else result


def execute_db(query, args=(), commit=True):
    """Execute a database query and optionally commit the changes."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(query, args)
    if commit:
        conn.commit()  # Ensure changes are saved to the database
    conn.close()


def init_db():
    """Initialize the database schema."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_manager INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            type TEXT NOT NULL,
            tags TEXT,
            organizer TEXT NOT NULL,
            date TEXT NOT NULL, 
            time TEXT NOT NULL,  
            location TEXT NOT NULL,
            description TEXT,
            image_url TEXT
        );
        CREATE TABLE IF NOT EXISTS signups (
            user_id INTEGER,
            event_id INTEGER,
            PRIMARY KEY (user_id, event_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (event_id) REFERENCES events (id)
        );
        ''')
        conn.commit()

