from datetime import datetime
import sqlite3
from werkzeug.utils import secure_filename
import os


def insert_events(events, upload_folder):
    conn = sqlite3.connect('event_management.db')
    cursor = conn.cursor()

    for event in events:
        # Check if the event already exists by title and date
        cursor.execute('''
            SELECT COUNT(*) FROM events WHERE title = ? AND date = ?
        ''', (event['title'], event['date']))
        event_exists = cursor.fetchone()[0] > 0

        if not event_exists:
            # Handle the image upload (if exists)
            image_url = None
            image = event.get('image_url')
            if image:
                image_filename = secure_filename(image)
                image_path = os.path.join(upload_folder, image_filename)
                image_url = f'uploads/{image_filename}'  # Store relative path to the static folder

            organizer = event.get('organizer', 'Default Organizer')  # Default organizer
            organizer_id = event.get('organizer_id', 1)  # Default organizer_id

            cursor.execute('''
                INSERT INTO events (title, type, tags, organizer, organizer_id, date, time, location, description, image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['title'], event['type'], event['tags'], organizer, organizer_id,
                event['date'], event['time'], event['location'], event['description'], image_url
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
        'image_url': 'pitt_career_fair.png'  # Simplified image URL
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
        'image_url': 'pitt_arts_showcase.jpg'  # Simplified image URL
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
        'image_url': 'pitt_homecoming.jpg'  # Simplified image URL
    },
        # Add more University of Pittsburgh-related events here
]


def get_upcoming_events(filters=None):
    current_date = datetime.now().strftime('%Y-%m-%d')

    # Initial list of upcoming events
    filtered_events = [event for event in events if event['date'] >= current_date]

    # Apply filters
    if filters:
        if 'type' in filters and filters['type']:
            filtered_events = [event for event in filtered_events if event['type'] == filters['type']]
        if 'location' in filters and filters['location']:
            filtered_events = [event for event in filtered_events if
                               filters['location'].lower() in event['location'].lower()]
        if 'date' in filters and filters['date']:
            filtered_events = [event for event in filtered_events if event['date'] == filters['date']]

    return filtered_events

