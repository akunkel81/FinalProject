from datetime import datetime
import sqlite3


def insert_events(events):
    conn = sqlite3.connect('event_management.db')
    cursor = conn.cursor()

    for event in events:
        # Check if the event already exists by title and date
        cursor.execute('''
            SELECT COUNT(*) FROM events WHERE title = ? AND date = ?''',
                       (event['title'], event['date']))
        event_exists = cursor.fetchone()[0] > 0

        if not event_exists:
            # Insert the event if it doesn't already exist
            organizer_id = event.get('organizer_id', 1)  # Default organizer_id
            cursor.execute('''
                INSERT INTO events (title, type, tags, organizer_id, date, time, location, description, image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                event['title'], event['type'], event['tags'], organizer_id, event['date'],
                event['time'], event['location'], event['description'], event['image_url']
            ))

    conn.commit()
    conn.close()


events = [
    {
        'id': 1,
        'title': 'University of Pittsburgh Career Fair 2024',
        'type': 'Career Fair',
        'tags': 'Career, Networking, Job Fair, University of Pittsburgh, 2024, Student Success',
        'organizer': 'University of Pittsburgh Career Services',
        'organizer_id': 1,
        'date': '2024-12-10',
        'time': '09:00:00',
        'location': 'University of Pittsburgh - William Pitt Union',
        'description': 'A career fair for University of Pittsburgh students to connect with top employers.',
        'image_url': 'static/uploads/pitt_career_fair.png'  # New image URL
     },
     {
        'id': 2,
        'title': 'Pitt Arts Showcase 2024',
        'type': 'Arts',
        'tags': 'Arts, Music, Theater, University of Pittsburgh, Showcase, Culture',
        'organizer': 'Pitt Arts',
        'organizer_id': 1,
        'date': '2024-12-15',
        'time': '18:00:00',
        'location': 'University of Pittsburgh - Cathedral of Learning',
        'description': 'An evening showcasing the best of Pitt student talent in music, theater, and visual arts.',
        'image_url': 'static/uploads/pitt_arts_showcase.jpg'  # New image URL
    },
    {
        'id': 3,
        'title': 'Pitt Homecoming 2024',
        'type': 'Celebration',
        'tags': 'Homecoming, Alumni, University of Pittsburgh, Celebration, Sports',
        'organizer': 'University of Pittsburgh Alumni Association',
        'organizer_id': 1,
        'date': '2024-11-01',
        'time': '12:00:00',
        'location': 'University of Pittsburgh - Oakland Campus',
        'description': 'A festive celebration for Pitt alumni, students, and families.',
        'image_url': 'static/uploads/pitt_homecoming.jpg'  # New image URL
    },
        # Add more University of Pittsburgh-related events here
]

insert_events(events)


def get_upcoming_events():
    current_date = datetime.now().strftime('%Y-%m-%d')
    upcoming_events = [event for event in events if event['date'] >= current_date]
    return upcoming_events

def create_events_table():
    conn = sqlite3.connect('event_management.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        type TEXT NOT NULL,
        tags TEXT,
        organizer_id INTEGER,
        organizer TEXT,
        date TEXT NOT NULL,
        time TEXT,
        location TEXT NOT NULL,
        description TEXT,
        image_url TEXT,
        FOREIGN KEY (organizer_id) REFERENCES users(id)
    );
    ''')

    conn.commit()
    conn.close()

# Create the 'events' table
create_events_table()


