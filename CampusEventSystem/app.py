from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from sqlite3 import IntegrityError
from database import init_db, query_db, execute_db
from events_data import events, insert_events, get_upcoming_events
import os
from datetime import datetime

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'campuseventsystem'
bcrypt = Bcrypt(app)

DATABASE = 'event_management.db'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///event_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    init_db()
    print('Initialized the database.')

if __name__ == "__main__":
    app.run(debug=True)

@app.route('/', methods=['GET', 'POST'])
def home():
    rows = query_db("SELECT * FROM events")
    events = [dict(row) for row in rows]

    # Get the current date and time
    current_datetime = datetime.now()
    current_date = current_datetime.strftime('%Y-%m-%d')
    current_time = current_datetime.strftime('%H:%M:%S')

    upcoming_events = []
    for event in events:
        event_date = datetime.strptime(event['date'], "%Y-%m-%d")
        try:
            event_time = datetime.strptime(event['time'], "%H:%M").time()  # Adjusted format
        except ValueError:
            event_time = datetime.min.time()  # Default to midnight if time is invalid or missing

        event_datetime = datetime.combine(event_date, event_time)
        if event_datetime >= current_datetime:
            upcoming_events.append(event)

    filtered_events = events
    filter_criteria = {}
    if request.method == 'POST':
        filter_criteria['type'] = request.form.get('type')
        filter_criteria['location'] = request.form.get('location')
        filter_criteria['date'] = request.form.get('date')

        if filter_criteria['type']:
            filtered_events = [event for event in filtered_events if event['type'] == filter_criteria['type']]
        if filter_criteria['location']:
            filtered_events = [event for event in filtered_events if filter_criteria['location'].lower() in event['location'].lower()]
        if filter_criteria['date']:
            filtered_events = [event for event in filtered_events if event['date'] == filter_criteria['date']]

        upcoming_events = [event for event in filtered_events if datetime.strptime(event['date'], "%Y-%m-%d") >= current_datetime]

    return render_template(
        'index.html',
        upcoming_events=upcoming_events,
        all_events=filtered_events,
        current_date=current_date,
        current_time=current_time,
        filter_criteria=filter_criteria
    )




@app.route('/')
def index():
    filtered_events = [event for event in events if event['title'] != 'Event 1']

    for event in filtered_events:
        event['image_url'] = url_for('static', filename=f"uploads/{event['image']}")

    return render_template('index.html', events=filtered_events)

@app.route('/search', methods=['POST'])
def search():
    keyword = request.form.get('keyword', '')
    filter_criteria = {
        'type': request.form.get('type', ''),
        'location': request.form.get('location', ''),
        'date': request.form.get('date', ''),
    }

    query = "SELECT * FROM events WHERE (title LIKE ? OR tags LIKE ?)"
    params = [f"%{keyword}%", f"%{keyword}%"]

    if filter_criteria['type']:
        query += " AND type = ?"
        params.append(filter_criteria['type'])

    if filter_criteria['location']:
        query += " AND location LIKE ?"
        params.append(f"%{filter_criteria['location']}%")

    if filter_criteria['date']:
        query += " AND date = ?"
        params.append(filter_criteria['date'])

    rows = query_db(query, params)
    events = [dict(row) for row in rows]


    current_datetime = datetime.now()
    current_date = current_datetime.strftime('%Y-%m-%d')
    current_time = current_datetime.strftime('%H:%M:%S')

    upcoming_events = []
    for event in events:
        event_date = datetime.strptime(event['date'], "%Y-%m-%d")
        try:
            event_time = datetime.strptime(event['time'], "%H:%M").time()
        except ValueError:
            event_time = datetime.min.time()

        event_datetime = datetime.combine(event_date, event_time)
        if event_datetime >= current_datetime:
            upcoming_events.append(event)

    return render_template(
        'index.html',
        upcoming_events=upcoming_events,
        all_events=events,
        current_date=current_date,
        current_time=current_time,
        filter_criteria=filter_criteria
    )



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']


        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            execute_db('''
                INSERT INTO users (username, email, password, role)
                VALUES (?, ?, ?, ?)''', (username, email, hashed_password, role))
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            flash('Error: Username or email already exists.', 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']


        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)

        if user:
            try:
                if bcrypt.check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['role'] = user['role']  # Ensure this is 'event_manager' for managers
                    session['username'] = user['username']  # Set username in the session
                    flash('Login successful!', 'success')
                    return redirect(url_for('profile'))
            except ValueError:
                flash('Corrupted password detected. Please reset your password.', 'danger')
                return redirect(url_for('login'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')




@app.route('/rehash_passwords')
def rehash_passwords():
    # Fetch all users from the database
    users = query_db("SELECT * FROM users")

    for user in users:
        try:
            bcrypt.check_password_hash(user['password'], 'dummy_password')
        except (ValueError, TypeError):
            # Rehash plaintext or corrupted password
            plaintext_password = user['password']  # Assuming plaintext was stored for rehashing
            new_hash = bcrypt.generate_password_hash(plaintext_password).decode('utf-8')
            # Update the password in the database
            execute_db("UPDATE users SET password = ? WHERE id = ?", (new_hash, user['id']))

    flash('All passwords have been successfully rehashed.', 'success')
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('You need to be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = query_db("SELECT * FROM users WHERE id = ?", [user_id], one=True)

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password and password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('settings'))


        existing_user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        if existing_user and existing_user['id'] != user_id:
            flash('Username is already taken. Please choose another one.', 'danger')
            return redirect(url_for('settings'))


        existing_email = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)
        if existing_email and existing_email['id'] != user_id:
            flash('Email is already in use. Please choose another one.', 'danger')
            return redirect(url_for('settings'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') if password else None

        try:
            if hashed_password:
                execute_db(
                    '''
                    UPDATE users
                    SET username = ?, email = ?, password = ?
                    WHERE id = ?
                    ''',
                    (username, email, hashed_password, user_id)
                )
            else:
                execute_db(
                    '''
                    UPDATE users
                    SET username = ?, email = ?
                    WHERE id = ?
                    ''',
                    (username, email, user_id)
                )

            session['username'] = username

            flash('Your changes have been saved successfully!', 'success')
            return redirect(url_for('settings'))

        except Exception as e:
            flash(f"An error occurred: {e}", 'danger')
            return redirect(url_for('settings'))

    return render_template('settings.html', user=user)



@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']

    upcoming_events = query_db(
        "SELECT * FROM events WHERE id IN (SELECT event_id FROM signups WHERE user_id = ?) AND date >= DATE('now')",
        (user_id,)
    )

    all_upcoming_events = query_db(
        "SELECT * FROM events WHERE date >= DATE('now') ORDER BY date"
    )

    return render_template('profile.html', upcoming_events=upcoming_events, all_upcoming_events=all_upcoming_events)


UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


insert_events(events, UPLOAD_FOLDER)


@app.route('/manager/dashboard')
def manager_dashboard():
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can view this page.', 'danger')
        return redirect(url_for('profile'))

    user_id = session['user_id']

    upcoming_events = query_db(
        "SELECT * FROM events WHERE organizer_id = ? AND date >= DATE('now') ORDER BY date",
        (user_id,)
    )
    past_events = query_db(
        "SELECT * FROM events WHERE organizer_id = ? AND date < DATE('now') ORDER BY date DESC",
        (user_id,)
    )

    return render_template('manager_dashboard.html', upcoming_events=upcoming_events, past_events=past_events)

@app.route('/manager/batch_cancel_events', methods=['POST'])
def batch_cancel_events():
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can perform this action.', 'danger')
        return redirect(url_for('profile'))

    event_ids = request.form.getlist('event_ids')  # Get the list of selected event IDs

    if not event_ids:
        flash('No events selected for cancellation.', 'danger')
        return redirect(url_for('manager_dashboard'))

    try:
        # Using a transaction to delete multiple events at once
        execute_db("DELETE FROM events WHERE id IN ({})".format(','.join('?' * len(event_ids))), event_ids)
        flash('Selected events have been cancelled successfully.', 'success')
    except Exception as e:
        flash(f"An error occurred while canceling events: {e}", 'danger')

    return redirect(url_for('manager_dashboard'))


@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = query_db("SELECT * FROM events WHERE id = ?", [event_id], one=True)

    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('home'))

    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')

    is_registered = False
    if 'user_id' in session:
        user_id = session['user_id']
        signup = query_db("SELECT * FROM signups WHERE user_id = ? AND event_id = ?", [user_id, event_id], one=True)
        is_registered = signup is not None

    # Count attendees
    attendees_count = query_db("SELECT COUNT(*) AS count FROM signups WHERE event_id = ?", [event_id], one=True)[
        'count']


    attendees = query_db("""
        SELECT users.username, users.email 
        FROM signups 
        JOIN users ON signups.user_id = users.id 
        WHERE signups.event_id = ?
    """, [event_id])

    is_event_manager = session.get('role') == 'event_manager' and event['organizer_id'] == session['user_id']

    return render_template(
        'event_detail.html',
        event=event,
        current_date=current_date,
        current_time=current_time,
        is_registered=is_registered,
        attendees=attendees,
        attendees_count=attendees_count,
        is_event_manager=is_event_manager
    )


@app.route('/manager/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can create events.', 'danger')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        title = request.form['title']
        event_type = request.form['type']
        date = request.form['date']
        time = request.form['time']
        location = request.form['location']
        description = request.form['description']
        tags = request.form.get('tags')
        organizer = session['username']

        organizer_id = session['user_id']


        image = request.files.get('image')
        image_url = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)
            image_url = f'uploads/{image_filename}'


        execute_db(
            '''
            INSERT INTO events (title, type, tags, organizer_id, organizer, date, time, location, description, image_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (title, event_type, tags, organizer_id, organizer, date, time, location, description, image_url)
        )

        flash('Event created successfully!', 'success')
        return redirect(url_for('manager_dashboard'))

    return render_template('create_event.html')



@app.route('/manager/event/<int:event_id>')
def manage_event(event_id):
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    user_id = session['user_id']
    event = query_db("SELECT * FROM events WHERE id = ? AND organizer_id = ?", (event_id, user_id), one=True)
    if not event:
        flash('Event not found or you do not have permission to manage it.', 'danger')
        return redirect(url_for('manager_dashboard'))

    attendees = query_db(
        "SELECT u.username, u.email FROM users u JOIN signups s ON u.id = s.user_id WHERE s.event_id = ?",
        (event_id,)
    )

    return render_template('manage_events.html', event=event, attendees=attendees)

@app.route('/manager/event/<int:event_id>/edit', methods=['GET', 'POST'])
def edit_event(event_id):
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can edit events.', 'danger')
        return redirect(url_for('home'))

    user_id = session['user_id']
    event = query_db("SELECT * FROM events WHERE id = ?", [event_id], one=True)

    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('manager_dashboard'))

    if event['organizer_id'] != user_id:
        flash('You do not have permission to edit this event.', 'danger')
        return redirect(url_for('manager_dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        event_type = request.form['type']
        date = request.form['date']
        time = request.form['time']
        location = request.form['location']
        description = request.form['description']


        image = request.files.get('image')
        image_url = event['image_url']

        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)
            image_url = f'uploads/{image_filename}'

            print(f"Image uploaded successfully: {image_url}")
        else:
            print("No new image uploaded. Retaining existing image.")

        print(f"Updating event {event_id} with new image_url: {image_url}")

        execute_db('''
            UPDATE events
            SET title = ?, type = ?, date = ?, time = ?, location = ?, description = ?, image_url = ?
            WHERE id = ? AND organizer_id = ?
        ''', (title, event_type, date, time, location, description, image_url, event_id, user_id))

        flash('Event updated successfully!', 'success')
        return redirect(url_for('manager_dashboard'))

    return render_template('edit_event.html', event=event)


@app.route('/manager/event/<int:event_id>/cancel', methods=['POST'])
def cancel_event(event_id):
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    user_id = session['user_id']
    event = query_db("SELECT * FROM events WHERE id = ? AND organizer_id = ?", [event_id, user_id], one=True)

    if not event:
        flash('Event not found or you do not have permission to cancel it.', 'danger')
        return redirect(url_for('manager_dashboard'))

    execute_db("DELETE FROM events WHERE id = ? AND organizer_id = ?", [event_id, user_id])
    flash('Event canceled successfully.', 'success')
    return redirect(url_for('manager_dashboard'))


@app.route('/signup/<int:event_id>', methods=['POST'])
def signup(event_id):
    if 'user_id' not in session:
        flash('You need to be logged in to sign up for an event', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    event = query_db("SELECT * FROM events WHERE id = ?", [event_id], one=True)

    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('home'))

    event_date = datetime.strptime(event['date'], "%Y-%m-%d")
    if event_date < datetime.now():
        flash('You cannot sign up for past events.', 'danger')
        return redirect(url_for('home'))

    # Check if the user is already signed up for the event
    existing_signup = query_db(
        "SELECT * FROM signups WHERE user_id = ? AND event_id = ?",
        [user_id, event_id],
        one=True
    )
    if existing_signup:
        flash('You are already signed up for this event.', 'info')
        return redirect(url_for('event_detail', event_id=event_id))

    execute_db('''
        INSERT INTO signups (user_id, event_id)
        VALUES (?, ?)
    ''', (user_id, event_id))

    flash('You have successfully signed up for the event!', 'success')
    return redirect(url_for('event_detail', event_id=event_id))



@app.route('/event/<int:event_id>/cancel_signup', methods=['POST'])
def cancel_signup(event_id):
    if 'user_id' not in session:
        flash('You need to log in to cancel your signup.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    is_signed_up = query_db(
        "SELECT * FROM signups WHERE user_id = ? AND event_id = ?",
        (user_id, event_id), one=True
    )

    # Debugging line
    print(f"Is signed up: {is_signed_up}")

    if not is_signed_up:
        flash('You are not signed up for this event.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))

    execute_db(
        "DELETE FROM signups WHERE user_id = ? AND event_id = ?",
        (user_id, event_id)
    )

    # Debugging line
    print(f"Deleted signup for user {user_id} and event {event_id}")

    flash('Your signup was successfully canceled.', 'success')
    return redirect(url_for('event_detail', event_id=event_id))