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

-- Recreate the events table with both 'organizer' and 'organizer_id'
CREATE TABLE new_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    type TEXT NOT NULL,
    tags TEXT,
    organizer TEXT NOT NULL,  -- Make sure it's NOT NULL
    organizer_id INTEGER NOT NULL,  -- This is now a foreign key
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    location TEXT NOT NULL,
    description TEXT,
    image_url TEXT,
    FOREIGN KEY (organizer_id) REFERENCES users(id)
);

-- Insert the data from old events table
INSERT INTO new_events (id, title, type, tags, organizer, organizer_id, date, time, location, description, image_url)
SELECT id, title, type, tags, organizer, organizer_id, date, time, location, description, image_url
FROM events;

-- Drop the old events table
DROP TABLE events;

-- Rename the new events table to the original table name
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


