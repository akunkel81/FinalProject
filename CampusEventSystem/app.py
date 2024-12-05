from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from sqlite3 import IntegrityError
from database import init_db, query_db, execute_db
from events_data import events, get_upcoming_events
import os

app = Flask(__name__)
app.secret_key = 'campuseventsystem'
bcrypt = Bcrypt(app)

DATABASE = 'event_management.db'  # File in the same folder as app.py

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///event_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Optional, disables unnecessary tracking

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    init_db()
    print('Initialized the database.')

if __name__ == "__main__":
    app.run(debug=True)

@app.route('/')
def home():
    # Fetch all upcoming events, sorted by date
    events = query_db("SELECT * FROM events WHERE date >= DATE('now') ORDER BY date")

    return render_template('index.html', events=events)

@app.route('/')
def index():
    # Exclude specific event dynamically
    filtered_events = [event for event in events if event['title'] != 'Event 1']

    for event in filtered_events:
        event['image_url'] = url_for('static', filename=f"uploads/{event['image']}")

    return render_template('index.html', events=filtered_events)

@app.route('/search', methods=['POST'])
def search():
    keyword = request.form['keyword']

    # Search by title or tags, case-insensitive
    filtered_events = query_db("""
        SELECT * FROM events
        WHERE title LIKE ? OR tags LIKE ?
        AND date >= DATE('now')
    """, ('%' + keyword + '%', '%' + keyword + '%'))

    return render_template('index.html', events=filtered_events)


@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = query_db("SELECT * FROM events WHERE id = ?", (event_id,), one=True)
    attendees = query_db("SELECT COUNT(*) as count FROM signups WHERE event_id = ?", (event_id,), one=True)
    is_registered = query_db("SELECT * FROM signups WHERE user_id = ? AND event_id = ?",
                             (session.get('user_id'), event_id), one=True)
    return render_template('event_detail.html', event=event, attendees=attendees['count'], is_registered=bool(is_registered))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # Get the selected role (user or admin)

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            # Insert the new user into the database
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

        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']  # Ensure this is 'event_manager' for managers
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Query the events the user is signed up for
    upcoming_events = query_db(
        "SELECT * FROM events WHERE id IN (SELECT event_id FROM signups WHERE user_id = ?) AND date >= DATE('now')",
        (user_id,)
    )

    # Query all upcoming events
    all_upcoming_events = query_db(
        "SELECT * FROM events WHERE date >= DATE('now') ORDER BY date"
    )

    return render_template('profile.html', upcoming_events=upcoming_events, all_upcoming_events=all_upcoming_events)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/manager/dashboard')
def manager_dashboard():
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can view this page.', 'danger')
        return redirect(url_for('profile'))

    user_id = session['user_id']

    # Fetch upcoming and past events managed by the logged-in user
    upcoming_events = query_db(
        "SELECT * FROM events WHERE organizer_id = ? AND date >= DATE('now') ORDER BY date",
        (user_id,)
    )
    past_events = query_db(
        "SELECT * FROM events WHERE organizer_id = ? AND date < DATE('now') ORDER BY date DESC",
        (user_id,)
    )

    return render_template('manager_dashboard.html', upcoming_events=upcoming_events, past_events=past_events)

@app.route('/manager/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session or session.get('role') != 'event_manager':
        flash('Access denied. Only event managers can create events.', 'danger')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        title = request.form['title']
        event_type = request.form['type']
        date = request.form['date']
        time = request.form['time']  # Get the time from the form
        location = request.form['location']
        description = request.form['description']
        tags = request.form.get('tags', '')  # Get tags from form, default to empty string if not provided
        organizer_id = session['user_id']

        # Handle image upload
        image = request.files.get('image')
        image_url = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)
            image_url = f'uploads/{image_filename}'  # Relative path for static folder

        # Insert the event into the database, ensuring 'time' is passed
        execute_db('''
            INSERT INTO events (title, type, tags, organizer_id, date, time, location, description, image_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (title, event_type, tags, organizer_id, date, time, location, description, image_url)
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
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    user_id = session['user_id']

    # Fetch the event by ID and ensure the manager owns it
    event = query_db(
        "SELECT * FROM events WHERE id = ? AND organizer_id = ?",
        (event_id, user_id),
        one=True
    )

    if not event:
        flash('Event not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('manager_dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        event_type = request.form['type']
        date = request.form['date']
        time = request.form['time']  # Get the time from the form
        location = request.form['location']
        description = request.form['description']

        # Handle optional image update
        image = request.files.get('image')
        image_url = event['image_url']
        if image and allowed_file(image.filename):
            image_url = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_url)

        # Update the event in the database, including the time field
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
        return redirect(url_for('index'))

    user_id = session['user_id']
    event = query_db("SELECT * FROM events WHERE id = ? AND organizer_id = ?", (event_id, user_id), one=True)
    if not event:
        flash('Event not found or you do not have permission to cancel it.', 'danger')
        return redirect(url_for('manager_dashboard'))

    execute_db("DELETE FROM events WHERE id = ? AND organizer_id = ?", (event_id, user_id))
    flash('Event canceled successfully.', 'success')
    return redirect(url_for('manager_dashboard'))


@app.route('/signup/<int:event_id>', methods=['POST'])
def signup(event_id):
    if 'user_id' not in session:
        flash('Please log in to register for the event.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    try:
        execute_db("INSERT INTO signups (user_id, event_id) VALUES (?, ?)", (user_id, event_id))
        flash('Successfully signed up for the event!', 'success')
    except IntegrityError:
        flash('You are already registered for this event.', 'info')

    return redirect(url_for('event_detail', event_id=event_id))


@app.route('/event/<int:event_id>/cancel_signup', methods=['POST'])
def cancel_signup(event_id):
    if 'user_id' not in session:
        flash('You need to log in to cancel your signup.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Check if the user is signed up for the event
    is_signed_up = query_db(
        "SELECT * FROM signups WHERE user_id = ? AND event_id = ?",
        (user_id, event_id), one=True
    )

    # Debugging line
    print(f"Is signed up: {is_signed_up}")

    if not is_signed_up:
        flash('You are not signed up for this event.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))

    # Remove the signup from the database
    execute_db(
        "DELETE FROM signups WHERE user_id = ? AND event_id = ?",
        (user_id, event_id)
    )

    # Debugging line
    print(f"Deleted signup for user {user_id} and event {event_id}")

    flash('Your signup was successfully canceled.', 'success')
    return redirect(url_for('event_detail', event_id=event_id))