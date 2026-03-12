from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import re
import hashlib
import os
import nltk
from nltk import pos_tag, word_tokenize
from command_injection_detector import detect_command_injection
from sqli_detector import detect_sqli, get_attack_explanation
from datetime import datetime

# Download required NLTK packages if not already downloaded
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
def connect_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = connect_db()
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Initialize database if it doesn't exist
if not os.path.exists('database.db'):
    init_db()

# Log detected attack to database
def log_attack(input_text, source_field, attack_info, ip_address, user_agent=None):
    """
    Logs detected SQL injection or command injection attempts to the database.
    """
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Prepare attack details
        attack_type = attack_info.get('attack_type', 'Unknown')
        severity = attack_info.get('severity', 'low')
        matched_pattern = str(attack_info.get('matched_pattern', ''))
        pos_analysis = str(attack_info.get('pos_analysis', {}))
        
        # Get user agent if not provided
        if user_agent is None:
            user_agent = request.headers.get('User-Agent', 'Unknown')
        
        print(f"[LOG] Logging attack: {attack_type} from {ip_address}")  # Debug
        
        cursor.execute("""
            INSERT INTO attack_logs 
            (input_text, source_field, attack_type, severity, matched_pattern, pos_analysis, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (input_text, source_field, attack_type, severity, matched_pattern, pos_analysis, ip_address, user_agent))
        
        conn.commit()
        conn.close()
        print(f"[LOG] Attack logged successfully!")  # Debug
        return True
    except Exception as e:
        print(f"Error logging attack: {e}")
        import traceback
        traceback.print_exc()
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        # Check for SQL injection in username
        sqli_result_username = detect_sqli(username)
        if sqli_result_username['is_sqli']:
            log_attack(username, 'login_username', sqli_result_username, ip_address)
            flash(f'SQL Injection detected in username field! Attack Type: {sqli_result_username["attack_type"]}', 'danger')
            return render_template('login.html')
        
        # Check for SQL injection in password
        sqli_result_password = detect_sqli(password)
        if sqli_result_password['is_sqli']:
            log_attack(password, 'login_password', sqli_result_password, ip_address)
            flash(f'SQL Injection detected in password field! Attack Type: {sqli_result_password["attack_type"]}', 'danger')
            return render_template('login.html')
            
        # Check for command injection in username
        if detect_command_injection(username):
            log_attack(username, 'login_username', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in username field!', 'danger')
            return render_template('login.html')
            
        # Check for command injection in password
        if detect_command_injection(password):
            log_attack(password, 'login_password', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in password field!', 'danger')
            return render_template('login.html')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Connect to database and check credentials
        conn = connect_db()
        cursor = conn.cursor()
        
        # Use parameterized queries to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password_hash))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        # Check for SQL injection in username
        sqli_result_username = detect_sqli(username)
        if sqli_result_username['is_sqli']:
            log_attack(username, 'register_username', sqli_result_username, ip_address)
            flash(f'SQL Injection detected in username field! Attack Type: {sqli_result_username["attack_type"]}', 'danger')
            return render_template('register.html')
        
        # Check for SQL injection in password
        sqli_result_password = detect_sqli(password)
        if sqli_result_password['is_sqli']:
            log_attack(password, 'register_password', sqli_result_password, ip_address)
            flash(f'SQL Injection detected in password field! Attack Type: {sqli_result_password["attack_type"]}', 'danger')
            return render_template('register.html')
        
        # Check for command injection
        if detect_command_injection(username):
            log_attack(username, 'register_username', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in username field!', 'danger')
            return render_template('register.html')
            
        if detect_command_injection(password):
            log_attack(password, 'register_password', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in password field!', 'danger')
            return render_template('register.html')
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Username can only contain letters, numbers, and underscores.', 'danger')
            return render_template('register.html')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        # Add new user
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, password_hash))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/api/attacks')
def get_attacks():
    """
    API endpoint to fetch real attack data from the database.
    """
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Fetch all attack logs
        cursor.execute("""
            SELECT id, input_text, source_field, attack_type, severity, 
                   matched_pattern, pos_analysis, ip_address, timestamp,
                   user_agent
            FROM attack_logs
            ORDER BY timestamp DESC
        """)
        
        attacks = []
        for row in cursor.fetchall():
            attack = {
                'id': row['id'],
                'query': row['input_text'],
                'source': row['source_field'],
                'type': row['attack_type'],
                'severity': row['severity'],
                'matched_pattern': row['matched_pattern'],
                'pos_analysis': eval(row['pos_analysis']) if row['pos_analysis'] else {},
                'ip_address': row['ip_address'],
                'timestamp': row['timestamp'],
                'user_agent': row['user_agent'] if 'user_agent' in row.keys() else 'Unknown',
                'explanation': get_attack_explanation(row['attack_type'])
            }
            attacks.append(attack)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'attacks': attacks,
            'total': len(attacks)
        })
        
    except Exception as e:
        print(f"Error fetching attacks: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'attacks': [],
            'total': 0
        })

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    results = []
    if request.method == 'POST':
        search_term = request.form['search']
        ip_address = request.remote_addr
        
        # Check for SQL injection
        sqli_result = detect_sqli(search_term)
        if sqli_result['is_sqli']:
            log_attack(search_term, 'search_field', sqli_result, ip_address)
            flash(f'SQL Injection detected in search field! Attack Type: {sqli_result["attack_type"]}', 'danger')
            return render_template('search.html', results=results)
        
        # Check for command injection
        if detect_command_injection(search_term):
            log_attack(search_term, 'search_field', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in search field!', 'danger')
            return render_template('search.html', results=results)
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Search using parameterized query
        cursor.execute("SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?", 
                     ('%' + search_term + '%', '%' + search_term + '%'))
        results = cursor.fetchall()
        conn.close()
    
    return render_template('search.html', results=results)

@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        ip_address = request.remote_addr
        
        # Check for SQL injection in title
        sqli_result_title = detect_sqli(title)
        if sqli_result_title['is_sqli']:
            log_attack(title, 'post_title', sqli_result_title, ip_address)
            flash(f'SQL Injection detected in title field! Attack Type: {sqli_result_title["attack_type"]}', 'danger')
            return render_template('post.html')
        
        # Check for SQL injection in content
        sqli_result_content = detect_sqli(content)
        if sqli_result_content['is_sqli']:
            log_attack(content, 'post_content', sqli_result_content, ip_address)
            flash(f'SQL Injection detected in content field! Attack Type: {sqli_result_content["attack_type"]}', 'danger')
            return render_template('post.html')
            
        # Check for command injection
        if detect_command_injection(title):
            log_attack(title, 'post_title', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in title field!', 'danger')
            return render_template('post.html')
            
        if detect_command_injection(content):
            log_attack(content, 'post_content', {'attack_type': 'Command Injection', 'severity': 'high'}, ip_address)
            flash('Potential command injection detected in content field!', 'danger')
            return render_template('post.html')
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Get user id
        cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
        user = cursor.fetchone()
        
        # Add new post
        cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                     (title, content, user['id']))
        conn.commit()
        conn.close()
        
        flash('Post added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('post.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)