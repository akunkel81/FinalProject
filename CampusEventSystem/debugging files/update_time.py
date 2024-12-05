import sqlite3

def update_event_times():
    # Connect to the SQLite database
    conn = sqlite3.connect('event_management.db')
    cursor = conn.cursor()

    # Example events_data (replace with your actual events_data)
    events_data = [
        {'id': 1, 'time': '09:00:00'},
        {'id': 2, 'time': '14:00:00'},
        {'id': 3, 'time': '16:00:00'}
    ]

    # Loop through events_data and update the time in the database
    for event in events_data:
        cursor.execute('''
            UPDATE events
            SET time = ?
            WHERE id = ? AND time = '12:00'
        ''', (event['time'], event['id']))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

# Call the function to update event times
update_event_times()
