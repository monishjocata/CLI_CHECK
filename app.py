# app.py - Intentionally vulnerable Flask app for testing
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import subprocess
import pickle
import hashlib

app = Flask(__name__)
app.secret_key = "123456"  # Security Issue: Weak secret key

# Global variables - Code Quality Issue
USER_DATA = {}
CURRENT_USER = None
DB_PATH = "users.db"

def init_db():
    # Security Issue: No proper database connection handling
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT,
            author TEXT
        )
    """)
    conn.commit()
    # Bug: Connection not properly closed

@app.route('/')
def home():
    # Code Quality Issue: No error handling
    posts = get_all_posts()
    return render_template('home.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Security Issue: SQL Injection vulnerability
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        result = cursor.execute(query).fetchone()
        
        if result:
            session['user_id'] = result[0]
            session['username'] = result[1]
            return redirect(url_for('dashboard'))
        else:
            # Bug: No error message displayed
            pass
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Security Issue: Plain text password
        email = request.form['email']
        
        # Security Issue: No input validation
        # Bug: No duplicate username check
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, password, email))
        conn.commit()
        # Bug: No exception handling for database errors
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    # Security Issue: No authentication check
    username = session.get('username', 'Anonymous')
    
    # Code Quality Issue: Hardcoded HTML in Python
    welcome_msg = f"<h2>Welcome {username}!</h2>"  # Security Issue: XSS vulnerability
    
    return render_template('dashboard.html', welcome=welcome_msg)

@app.route('/profile')
def profile():
    user_id = session['user_id']  # Bug: KeyError if not logged in
    
    # Security Issue: No access control
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    user_data = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    return render_template('profile.html', user=user_data)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Security Issue: Command injection vulnerability
    if query:
        result = subprocess.run(f"grep -r '{query}' ./files/", shell=True, capture_output=True, text=True)
        search_results = result.stdout
    else:
        search_results = ""
    
    return render_template('search.html', results=search_results)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # Security Issue: No file type validation
    # Security Issue: Arbitrary file upload
    filename = file.filename
    file.save(f"./uploads/{filename}")  # Bug: No directory existence check
    
    return f"File {filename} uploaded successfully!"

@app.route('/admin')
def admin():
    # Security Issue: No role-based access control
    users = get_all_users()
    return render_template('admin.html', users=users)

@app.route('/backup')
def backup():
    # Security Issue: Arbitrary code execution via pickle
    backup_data = {
        'users': get_all_users(),
        'posts': get_all_posts()
    }
    
    with open('backup.pkl', 'wb') as f:
        pickle.dump(backup_data, f)  # Security Issue: Unsafe deserialization
    
    return "Backup created successfully!"

@app.route('/restore')
def restore():
    # Security Issue: Unsafe pickle loading
    try:
        with open('backup.pkl', 'rb') as f:
            data = pickle.load(f)  # Critical Security Issue
        return "Restore completed!"
    except:
        # Bug: Bare except clause, no specific error handling
        return "Restore failed!"

def get_all_users():
    # Code Quality Issue: Repetitive database code
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    users = cursor.execute("SELECT * FROM users").fetchall()
    # Bug: Connection not closed
    return users

def get_all_posts():
    # Code Quality Issue: Duplicate database pattern
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    posts = cursor.execute("SELECT * FROM posts").fetchall()
    # Bug: Connection not closed
    return posts

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    # Security Issue: No CSRF protection
    # Security Issue: No authorization check
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    
    return redirect(url_for('admin'))

@app.route('/api/user/<username>')
def api_get_user(username):
    # Security Issue: Information disclosure
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    user = cursor.execute("SELECT username, email, password FROM users WHERE username = ?", 
                         (username,)).fetchone()
    
    if user:
        # Security Issue: Exposing passwords in API
        return {
            'username': user[0],
            'email': user[1], 
            'password': user[2]  # Critical: Password exposure
        }
    else:
        return {'error': 'User not found'}, 404

def hash_password(password):
    # Security Issue: Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

def validate_input(data):
    # Code Quality Issue: Empty function
    pass

def log_activity(action, user_id):
    # Code Quality Issue: Function not implemented
    # Bug: Unused parameters
    print(f"Activity: {action}")

if __name__ == '__main__':
    init_db()
    # Security Issue: Debug mode in production
    # Security Issue: Running on all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000)