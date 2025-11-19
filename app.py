from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'shs_portal.db')

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'), static_folder=BASE_DIR)
app.secret_key = 'super-secret-key-change-me'

# Hardcoded admin secret (change as needed or set ADMIN_SECRET env var)
ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'adminpass')


def get_db_connection():
    # Increase timeout and allow connections from different threads
    # Enable WAL journal mode to reduce write-lock contention in concurrent scenarios
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # turn on WAL and foreign keys for better concurrency and integrity
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA foreign_keys=ON;')
    except Exception:
        # If PRAGMA fails for any reason, continue with the connection
        pass
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # users: id, name, email, password_hash, role
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT,
        role TEXT CHECK(role IN ('student','admin')) NOT NULL DEFAULT 'student',
        created_at TEXT
    )
    ''')

    # complaints: id, student_email, title, description, category, priority, status, admin_notes, created_at
    cur.execute('''
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT,
        title TEXT,
        description TEXT,
        category TEXT,
        priority TEXT,
        status TEXT DEFAULT 'pending',
        admin_notes TEXT,
        created_at TEXT
    )
    ''')

    # transcripts: id, student_email, type, copies, delivery_method, voucher_code, status, notes, created_at
    cur.execute('''
    CREATE TABLE IF NOT EXISTS transcripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT,
        type TEXT,
        copies INTEGER,
        delivery_method TEXT,
        voucher_code TEXT,
        status TEXT DEFAULT 'processing',
        notes TEXT,
        created_at TEXT
    )
    ''')

    # notifications: id, user_email, message, created_at, read_flag
    cur.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        message TEXT,
        created_at TEXT,
        read_flag INTEGER DEFAULT 0
    )
    ''')

    conn.commit()
    conn.close()


init_db()


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    name = request.form.get('fullName') or request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role') or 'student'

    if not (name and email and password):
        flash('Please provide name, email and password', 'error')
        return redirect(url_for('signup'))

    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
                    (name, email, password_hash, role, datetime.utcnow().isoformat()))
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        flash('An account with this email already exists', 'error')
        conn.close()
        return redirect(url_for('signup'))
    finally:
        # ensure connection closed if not already
        try:
            conn.close()
        except:
            pass

    # Auto-login after signup and redirect to appropriate dashboard
    session.clear()
    session['user_id'] = user_id
    session['email'] = email
    session['role'] = role
    session['name'] = name

    flash('Account created and signed in.', 'success')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('student_dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email')
    password = request.form.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))

    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    session['name'] = user['name']

    # flash success message
    flash('Logged in successfully.', 'success')

    if user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('student_dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))


@app.route('/password_reset')
def password_reset_page():
    return render_template('password_reset.html')


@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    data = request.get_json() or {}
    email = data.get('email')
    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return jsonify({'exists': bool(user)})


@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    data = request.get_json() or {}
    email = data.get('email')
    new_password = data.get('newPassword')
    if not (email and new_password):
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    # ensure the email exists
    existing = cur.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'success': False, 'message': 'No account found for that email'}), 404

    password_hash = generate_password_hash(new_password)
    cur.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/student/dashboard')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    return render_template('student_dashboard.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    email = request.form.get('adminEmail') or request.form.get('email')
    password = request.form.get('adminPassword') or request.form.get('password')
    # Allow a hardcoded admin password to access admin area. If ADMIN_SECRET
    # is used, create the admin user row if it doesn't exist so session can be set.
    # ADMIN_SECRET branch: create-or-get admin and sign in
    if password == ADMIN_SECRET:
        conn = get_db_connection()
        cur = conn.cursor()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        if not user:
            # create admin user with the secret as password (hashed)
            password_hash = generate_password_hash(password)
            cur.execute('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
                        (email.split('@')[0], email, password_hash, 'admin', datetime.utcnow().isoformat()))
            conn.commit()
            user = cur.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        conn.close()

        # set session and redirect
        session.clear()
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        session['name'] = user['name']
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    # Fallback to normal DB-backed admin authentication
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        flash('Invalid admin credentials', 'error')
        return redirect(url_for('admin_login'))

    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    session['name'] = user['name']
    flash('Logged in successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/api/complaints', methods=['POST', 'GET'])
def api_complaints():
    if request.method == 'POST':
        data = request.get_json() or {}
        student_email = data.get('student_email')
        title = data.get('title')
        description = data.get('description')
        category = data.get('category')
        priority = data.get('priority') or 'medium'
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO complaints (student_email, title, description, category, priority, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (student_email, title, description, category, priority, created_at))
        conn.commit()
        cid = cur.lastrowid
        # notify all admins about the new complaint
        admins = cur.execute("SELECT email FROM users WHERE role = 'admin'").fetchall()
        message = f'New complaint #{cid} by {student_email}: {title}'
        for a in admins:
            cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (a['email'], message, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': cid})

    # GET: list complaints
    email = request.args.get('email')
    conn = get_db_connection()
    if email:
        rows = conn.execute('SELECT * FROM complaints WHERE student_email = ? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM complaints ORDER BY created_at DESC').fetchall()
    conn.close()
    complaints = [dict(r) for r in rows]
    return jsonify({'complaints': complaints})


@app.route('/api/complaints/<int:complaint_id>/update', methods=['POST'])
def api_update_complaint(complaint_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    status = data.get('status')
    notes = data.get('notes')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE complaints SET status = ?, admin_notes = ? WHERE id = ?', (status, notes, complaint_id))
    conn.commit()

    # send notification to student
    row = conn.execute('SELECT student_email FROM complaints WHERE id = ?', (complaint_id,)).fetchone()
    if row:
        message = f'Your complaint #{complaint_id} status has been updated to: {status}'
        cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (row['student_email'], message, datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()
    return jsonify({'success': True})


@app.route('/api/transcripts/<int:transcript_id>/update', methods=['POST'])
def api_update_transcript(transcript_id):
    # only admins can update transcript requests
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json() or {}
    status = data.get('status')
    notes = data.get('notes')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE transcripts SET status = ?, notes = ? WHERE id = ?', (status, notes, transcript_id))
    conn.commit()

    # notify the student who requested the transcript
    row = conn.execute('SELECT student_email FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if row:
        message = f'Your transcript request #{transcript_id} status has been updated to: {status}'
        cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (row['student_email'], message, datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()
    return jsonify({'success': True})


@app.route('/api/transcripts', methods=['POST', 'GET'])
def api_transcripts():
    if request.method == 'POST':
        data = request.get_json() or {}
        student_email = data.get('student_email')
        ttype = data.get('type')
        copies = int(data.get('copies') or 1)
        delivery = data.get('delivery_method')
        voucher = data.get('voucher_code')
        notes = data.get('notes')
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO transcripts (student_email, type, copies, delivery_method, voucher_code, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (student_email, ttype, copies, delivery, voucher, notes, created_at))
        conn.commit()
        tid = cur.lastrowid
        conn.close()
        return jsonify({'success': True, 'id': tid})

    conn = get_db_connection()
    email = request.args.get('email')
    if email:
        rows = conn.execute('SELECT * FROM transcripts WHERE student_email = ? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM transcripts ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'transcripts': [dict(r) for r in rows]})


@app.route('/api/transcripts/<int:transcript_id>', methods=['DELETE'])
def api_delete_transcript(transcript_id):
    # allow admin or the student who created the request to delete it
    conn = get_db_connection()
    row = conn.execute('SELECT student_email FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404

    # authorization
    if session.get('role') != 'admin' and session.get('email') != row['student_email']:
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    cur = conn.cursor()
    cur.execute('DELETE FROM transcripts WHERE id = ?', (transcript_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/mark_read', methods=['POST'])
def api_notifications_mark_read():
    data = request.get_json() or {}
    email = data.get('email')
    ids = data.get('ids')
    mark_all = data.get('all')

    # only allow marking one's own notifications as read unless admin
    if session.get('email') != email and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    if ids and isinstance(ids, list) and len(ids) > 0:
        placeholders = ','.join('?' for _ in ids)
        params = [*ids, email]
        cur.execute(f'UPDATE notifications SET read_flag = 1 WHERE id IN ({placeholders}) AND user_email = ?', params)
    elif mark_all:
        cur.execute('UPDATE notifications SET read_flag = 1 WHERE user_email = ?', (email,))
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'No ids or all flag provided'}), 400

    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications', methods=['POST', 'GET'])
def api_notifications():
    if request.method == 'POST':
        data = request.get_json() or {}
        recipient = data.get('recipient')  # 'all' or specific email
        message = data.get('message')
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        if recipient == 'all':
            # send to all students
            users = conn.execute("SELECT email FROM users WHERE role='student'").fetchall()
            for u in users:
                cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (u['email'], message, created_at))
            # also add a copy for the sender (if logged in) so they can see the notification they sent
            sender_email = session.get('email')
            if sender_email:
                cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (sender_email, message, created_at))
        else:
            cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (recipient, message, created_at))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    # GET
    email = request.args.get('email')
    conn = get_db_connection()
    if email:
        rows = conn.execute('SELECT * FROM notifications WHERE user_email = ? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM notifications ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'notifications': [dict(r) for r in rows]})


@app.route('/api/users', methods=['GET'])
def api_users():
    # Only admins should retrieve full user lists
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    rows = conn.execute('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    users = [dict(r) for r in rows]
    return jsonify({'users': users})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    # only admins can delete users
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # prevent deleting yourself
    if session.get('user_id') == user_id:
        return jsonify({'success': False, 'message': "You can't delete your own account"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
