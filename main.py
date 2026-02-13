#!/usr/bin/env python3
"""
Cyber 20 UN - Full Web VPS Engine
Flask + SocketIO + SQLite + Subprocess Management
- Multi‑user with hashed passwords
- Each user has isolated workspace
- Deploy Flask apps on random ports
- Terminal with pip, python, etc.
"""

import os
import sys
import json
import uuid
import pty
import select
import signal
import shutil
import socket
import sqlite3
import threading
import time
import subprocess
import fcntl
import struct
import termios
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Flask & SocketIO
from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory
from flask_socketio import SocketIO, emit

# Optional: for detecting free port
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ==================== কনফিগারেশন ====================

DB_FILE = "cyber20un.db"
WORKSPACE_ROOT = "workspaces"   # প্রতিটি ইউজারের ফাইল এখানে থাকবে
MAX_PORT = 9999
MIN_PORT = 2000
PORT_RANGE = range(MIN_PORT, MAX_PORT + 1)

# অ্যাপ কনফিগারেশন
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# ==================== ডাটাবেস লেয়ার ====================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # ইউজার টেবিল
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            )
        """)
        # চলমান প্রসেস ট্র্যাকিং
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                pid INTEGER NOT NULL,
                port INTEGER NOT NULL,
                started_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # ডিফল্ট অ্যাডমিন ইউজার তৈরি (user: admin / pass: admin123)
        admin_exists = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            hashed = generate_password_hash('admin123')
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                ('admin', hashed, 1, int(time.time()))
            )
        conn.commit()
    print("[✓] Database initialized")

# ==================== ইউটিলিটি ফাংশন ====================

def get_user_dir(user_id):
    """ইউজারের ওয়ার্কস্পেস ফোল্ডার"""
    directory = os.path.join(WORKSPACE_ROOT, str(user_id))
    os.makedirs(directory, exist_ok=True)
    return directory

def is_port_free(port):
    """পোর্ট ফ্রি কিনা চেক"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except socket.error:
            return False

def find_free_port():
    """ব্যবহারযোগ্য একটি পোর্ট খুঁজে বের করে"""
    used_ports = set()
    with get_db() as conn:
        rows = conn.execute("SELECT port FROM processes").fetchall()
        used_ports = {r["port"] for r in rows}
    for port in PORT_RANGE:
        if port not in used_ports and is_port_free(port):
            return port
    raise RuntimeError("No free ports available")

def kill_process_by_pid(pid):
    """প্রসেস বন্ধ করে"""
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.3)
        # still alive? force kill
        try:
            os.kill(pid, signal.SIGKILL)
        except:
            pass
    except ProcessLookupError:
        pass
    except Exception as e:
        print(f"[!] Error killing PID {pid}: {e}")

# ==================== অথেনটিকেশন ডেকোরেটর ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        with get_db() as conn:
            user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ==================== ফাইল ও হোস্টিং ম্যানেজার ====================

def get_user_processes(user_id):
    """ইউজারের সব চলমান প্রসেসের তালিকা"""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM processes WHERE user_id = ?", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def stop_process(process_id, user_id):
    """প্রসেস বন্ধ করে ডাটাবেজ থেকে মুছে"""
    with get_db() as conn:
        proc = conn.execute("SELECT * FROM processes WHERE id = ? AND user_id = ?", (process_id, user_id)).fetchone()
        if proc:
            kill_process_by_pid(proc["pid"])
            conn.execute("DELETE FROM processes WHERE id = ?", (process_id,))
            conn.commit()
            return True
    return False

def start_flask_app(user_id, filename, full_path):
    """Flask অ্যাপ চালু করে (সাবপ্রসেস)"""
    port = find_free_port()
    # পরিবেশ ভেরিয়েবলে পোর্ট পাস করি
    env = os.environ.copy()
    env['PORT'] = str(port)
    env['PYTHONUNBUFFERED'] = '1'
    try:
        proc = subprocess.Popen(
            [sys.executable, filename],
            cwd=os.path.dirname(full_path),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        # ডাটাবেজে সেভ
        with get_db() as conn:
            conn.execute(
                "INSERT INTO processes (user_id, filename, pid, port, started_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, filename, proc.pid, port, int(time.time()))
            )
            conn.commit()
            proc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return proc_id, port
    except Exception as e:
        return None, str(e)

# ==================== ফ্লাস্ক রাউট (ওয়েব পেজ ও লগইন) ====================

@app.route('/')
def index():
    """মেইন পেজ – টেমপ্লেট রেন্ডার"""
    if 'user_id' in session:
        with get_db() as conn:
            user = conn.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            username = user['username'] if user else 'Unknown'
        return render_template('index.html', logged_in=True, username=username)
    return render_template('index.html', logged_in=False)

@app.route('/login', methods=['POST'])
def login():
    """লগইন এন্ডপয়েন্ট – JSON রেসপন্স"""
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({"success": True, "message": "Login successful"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ==================== সকেটআইও ইভেন্ট হ্যান্ডলার ====================

@socketio.on('connect')
@login_required
def handle_connect():
    emit('log', {'type': 'info', 'msg': 'Connected to Cyber 20 UN engine'})

@socketio.on('get_files')
@login_required
def handle_get_files():
    """ইউজারের ফাইল তালিকা + হোস্টিং স্ট্যাটাস"""
    user_id = session['user_id']
    work_dir = get_user_dir(user_id)
    files = []
    processes = get_user_processes(user_id)
    process_map = {p['filename']: p for p in processes}

    try:
        for f in os.listdir(work_dir):
            if os.path.isfile(os.path.join(work_dir, f)):
                file_info = {
                    'name': f,
                    'hosted': f in process_map,
                    'port': process_map[f]['port'] if f in process_map else None
                }
                files.append(file_info)
    except Exception as e:
        print(f"[!] get_files error: {e}")
    emit('file_list', {'files': files})

@socketio.on('save_run')
@login_required
def handle_save_run(data):
    """ফাইল সেভ করে (যদি ফ্ল্যাগ থাকে) হোস্ট শুরু করে"""
    user_id = session['user_id']
    filename = data.get('filename')
    code = data.get('code', '')

    if not filename:
        emit('log', {'type': 'error', 'msg': 'Filename required'})
        return

    # নিরাপদ ফাইলনেম নিশ্চিত
    filename = secure_filename(filename)
    if not filename:
        emit('log', {'type': 'error', 'msg': 'Invalid filename'})
        return

    work_dir = get_user_dir(user_id)
    filepath = os.path.join(work_dir, filename)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(code)
        emit('log', {'type': 'info', 'msg': f'File {filename} saved'})
    except Exception as e:
        emit('log', {'type': 'error', 'msg': f'Failed to save: {e}'})
        return

    # হোস্টিং শুরু করার চেষ্টা
    if filename.endswith('.py'):
        # আগের চলমান প্রসেস বন্ধ কর (যদি থাকে)
        for p in get_user_processes(user_id):
            if p['filename'] == filename:
                stop_process(p['id'], user_id)
                break

        proc_id, port_or_error = start_flask_app(user_id, filename, filepath)
        if proc_id:
            emit('log', {
                'type': 'output',
                'msg': f'🚀 Hosted on port {port_or_error}',
                'filename': filename,
                'port': port_or_error
            })
        else:
            emit('log', {'type': 'error', 'msg': f'Hosting failed: {port_or_error}'})

    handle_get_files()  # ফাইল তালিকা রিফ্রেশ

@socketio.on('load_file')
@login_required
def handle_load_file(data):
    """ফাইল কন্টেন্ট লোড করে এডিটরে দেখায়"""
    user_id = session['user_id']
    filename = data.get('filename')
    filename = secure_filename(filename)
    if not filename:
        emit('log', {'type': 'error', 'msg': 'Invalid filename'})
        return

    work_dir = get_user_dir(user_id)
    filepath = os.path.join(work_dir, filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        emit('file_data', {'filename': filename, 'code': code})
        emit('log', {'type': 'info', 'msg': f'Loaded {filename}'})
    except Exception as e:
        emit('log', {'type': 'error', 'msg': f'Failed to load: {e}'})

@socketio.on('stop_hosting')
@login_required
def handle_stop_hosting(data):
    """নির্দিষ্ট ফাইলের হোস্টিং বন্ধ করে"""
    user_id = session['user_id']
    filename = data.get('filename')
    filename = secure_filename(filename)
    for p in get_user_processes(user_id):
        if p['filename'] == filename:
            stop_process(p['id'], user_id)
            emit('log', {'type': 'info', 'msg': f'Hosting stopped: {filename}'})
            break
    handle_get_files()

@socketio.on('delete_file')
@login_required
def handle_delete_file(data):
    """ফাইল ডিলিট – হোস্টিং থাকলে বন্ধ করে, তারপর ডিলিট"""
    user_id = session['user_id']
    filename = data.get('filename')
    filename = secure_filename(filename)
    if not filename:
        emit('log', {'type': 'error', 'msg': 'Invalid filename'})
        return

    # হোস্টিং বন্ধ
    for p in get_user_processes(user_id):
        if p['filename'] == filename:
            stop_process(p['id'], user_id)
            break

    work_dir = get_user_dir(user_id)
    filepath = os.path.join(work_dir, filename)
    try:
        os.remove(filepath)
        emit('log', {'type': 'info', 'msg': f'Deleted {filename}'})
    except Exception as e:
        emit('log', {'type': 'error', 'msg': f'Delete failed: {e}'})
    handle_get_files()

@socketio.on('execute_command')
@login_required
def handle_execute_command(data):
    """টার্মিনাল কমান্ড এক্সিকিউট – ইউজারের ওয়ার্কস্পেসে"""
    user_id = session['user_id']
    command = data.get('command')
    if not command:
        return

    work_dir = get_user_dir(user_id)
    emit('log', {'type': 'cmd', 'msg': command})

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            executable='/bin/bash'
        )
        for line in iter(proc.stdout.readline, ''):
            if line:
                emit('log', {'type': 'output', 'msg': line.rstrip()})
        proc.wait()
    except Exception as e:
        emit('log', {'type': 'error', 'msg': str(e)})

# ==================== অ্যাডমিন রাউট (ঐচ্ছিক) ====================

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def admin_create_user():
    """নতুন ইউজার তৈরি (শুধু অ্যাডমিন)"""
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin', 0, type=int)

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed = generate_password_hash(password)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed, is_admin, int(time.time()))
            )
            conn.commit()
        return jsonify({"success": True, "message": f"User {username} created"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

# ==================== স্ট্যাটিক ফাইল ও টেমপ্লেট ====================
# index.html টেমপ্লেটটি একই ফোল্ডারে রাখতে হবে

# ==================== মেইন ====================

if __name__ == '__main__':
    init_db()
    print("[✓] Starting Cyber 20 UN Engine...")
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
