-- Create the users table with the 'role' column
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',  -- Adding the 'role' column with default 'user'
    is_manager INTEGER DEFAULT 0
);

PRAGMA foreign_keys=off;

-- Create a new table without a default value for the time column
CREATE TABLE new_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    type TEXT NOT NULL,
    tags TEXT,
    organizer_id INTEGER,
    organizer TEXT,
    date TEXT NOT NULL,
    time TEXT,  -- No default value for time
    location TEXT NOT NULL,
    description TEXT,
    image_url TEXT,
    FOREIGN KEY (organizer_id) REFERENCES users(id)
);

-- Migrate the data from the old events table to the new one
INSERT INTO new_events (id, title, type, tags, organizer_id, organizer, date, time, location, description, image_url)
SELECT id, title, type, tags, organizer_id, organizer, date, time, location, description, image_url FROM events;

-- Drop the old events table
DROP TABLE events;

-- Rename the new table to events
ALTER TABLE new_events RENAME TO events;

PRAGMA foreign_keys=on;

-- Create the signups table if it doesn't already exist
CREATE TABLE IF NOT EXISTS signups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    signup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (event_id) REFERENCES events(id)
);

UPDATE events
SET time = (SELECT time FROM events_data WHERE events_data.id = events.id)
WHERE time = '12:00';
