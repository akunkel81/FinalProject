import sqlite3
from events_data import events  # Import events data from events_data.py

DATABASE = 'event_management.db'

def insert_events():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Insert events from events_data.py
    for event in events:
        cursor.execute("""
            INSERT INTO events (id, title, type, tags, organizer, date, location, description, image)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (event['id'], event['title'], event['type'], event['tags'], event['organizer'],
              event['date'], event['location'], event['description'], event['image']))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    insert_events()
    print("Events inserted into the database successfully.")
