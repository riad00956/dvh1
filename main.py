#!/usr/bin/env python3
"""
Telegram VPS Bot – Flask Integrated Version (Render Optimised)
- সব ফাইল সার্ভিস Flask‑এর ভিতরে, আলাদা পোর্টের দরকার নেই
- প্রতিটি VPS এর জন্য URL: https://yourdomain.com/vps/<instance_uuid>/
- লগইন, ফাইল আপলোড/ডাউনলোড/ডিলিট – সব Flask রুট
- Render‑এর 80/443 পোর্টেই কাজ করে
"""

import os
import sys
import json
import uuid
import logging
import threading
import sqlite3
import random
import string
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import parse_qs, unquote
import base64
import html
import shutil

# Third‑party
from dotenv import load_dotenv, set_key
import telebot
from telebot.types import (
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton,
    Update
)
from flask import (
    Flask, request, session, redirect, url_for, 
    send_file, abort, render_template_string, send_from_directory, make_response
)

# Optional
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ==================== কনফিগারেশন ====================

ENV_FILE = ".env"
load_dotenv(ENV_FILE)

DEFAULT_BOT_TOKEN = "8011804210:AAE--NiCSKKjbX4TC3nJVxuW64Fu53Ywh0w"
DEFAULT_OWNER_ID = 8373846582

BOT_TOKEN = os.getenv("BOT_TOKEN", DEFAULT_BOT_TOKEN)
OWNER_ID = os.getenv("OWNER_ID")
if not OWNER_ID:
    OWNER_ID = str(DEFAULT_OWNER_ID)
try:
    OWNER_ID = int(OWNER_ID)
except ValueError:
    logging.error("OWNER_ID must be an integer")
    sys.exit(1)

# Instance identity
INSTANCE_ID = os.getenv("INSTANCE_ID")
if not INSTANCE_ID:
    INSTANCE_ID = str(uuid.uuid4())[:8]
    set_key(ENV_FILE, "INSTANCE_ID", INSTANCE_ID)

INSTANCE_SECRET = os.getenv("INSTANCE_SECRET")
if not INSTANCE_SECRET:
    INSTANCE_SECRET = str(uuid.uuid4())
    set_key(ENV_FILE, "INSTANCE_SECRET", INSTANCE_SECRET)

# Render URL (স্বয়ংক্রিয়)
PUBLIC_URL = os.getenv("PUBLIC_URL", "")
if not PUBLIC_URL:
    PUBLIC_URL = os.getenv("RENDER_EXTERNAL_URL", "")
    if PUBLIC_URL:
        os.environ["PUBLIC_URL"] = PUBLIC_URL
        set_key(ENV_FILE, "PUBLIC_URL", PUBLIC_URL)

# Render পোর্ট
PORT = int(os.getenv("PORT", 10000))  # Render $PORT

# ডাটাবেস
DB_FILE = f"instance_{INSTANCE_ID}.db"

# ==================== লগিং ====================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("VPSBot")

# ==================== ডাটাবেস লেয়ার ====================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS core_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                duration_days INTEGER NOT NULL,
                max_servers INTEGER NOT NULL,
                used_count INTEGER DEFAULT 0,
                created_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_uuid TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                password TEXT NOT NULL,
                directory TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                core_key_id INTEGER,
                renewed_from INTEGER,
                status TEXT DEFAULT 'active'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                first_name TEXT,
                username TEXT,
                created_at INTEGER,
                last_interaction INTEGER,
                blocked INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at INTEGER NOT NULL,
                FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                action TEXT NOT NULL,
                user_id INTEGER,
                details TEXT
            )
        """)
        conn.commit()
    logger.info("Database initialized")

# ---------- Core Keys ----------
def generate_core_key(duration_days, max_servers, admin_id):
    key = "CORE-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    with get_db() as conn:
        conn.execute(
            "INSERT INTO core_keys (key, duration_days, max_servers, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
            (key, duration_days, max_servers, admin_id, int(time.time()))
        )
        conn.commit()
    return key

def get_core_key(key_str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM core_keys WHERE key = ? AND is_active = 1", (key_str,)).fetchone()
    return dict(row) if row else None

def increment_key_usage(key_id):
    with get_db() as conn:
        key = conn.execute("SELECT used_count, max_servers FROM core_keys WHERE id = ?", (key_id,)).fetchone()
        if key:
            used = key["used_count"] + 1
            conn.execute("UPDATE core_keys SET used_count = ? WHERE id = ?", (used, key_id))
            if used >= key["max_servers"]:
                conn.execute("UPDATE core_keys SET is_active = 0 WHERE id = ?", (key_id,))
        conn.commit()

def list_core_keys(active_only=True):
    with get_db() as conn:
        if active_only:
            rows = conn.execute("SELECT * FROM core_keys WHERE is_active = 1 ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM core_keys ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

# ---------- Instances ----------
def create_instance(user_id, core_key_id, duration_days, renewed_instance_id=None):
    if renewed_instance_id:
        with get_db() as conn:
            inst = conn.execute("SELECT * FROM instances WHERE id = ?", (renewed_instance_id,)).fetchone()
            if not inst:
                raise ValueError("Instance not found")
            new_expires = int((datetime.now() + timedelta(days=duration_days)).timestamp())
            conn.execute(
                "UPDATE instances SET expires_at = ?, core_key_id = ? WHERE id = ?",
                (new_expires, core_key_id, renewed_instance_id)
            )
            conn.commit()
            return renewed_instance_id, inst["instance_uuid"], inst["password"], inst["directory"]
    else:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        instance_uuid = str(uuid.uuid4())
        directory = f"instances/{instance_uuid}"
        os.makedirs(directory, exist_ok=True)

        created_at = int(time.time())
        expires_at = int((datetime.now() + timedelta(days=duration_days)).timestamp())

        with get_db() as conn:
            conn.execute("""
                INSERT INTO instances
                (instance_uuid, user_id, password, directory, created_at, expires_at, core_key_id, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (instance_uuid, user_id, password, directory, created_at, expires_at, core_key_id, 'active'))
            conn.commit()
            instance_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return instance_id, instance_uuid, password, directory

def get_instance_by_uuid(instance_uuid):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM instances WHERE instance_uuid = ?", (instance_uuid,)).fetchone()
    return dict(row) if row else None

def get_user_instances(user_id, include_expired=False):
    with get_db() as conn:
        query = "SELECT * FROM instances WHERE user_id = ?"
        params = [user_id]
        if not include_expired:
            query += " AND expires_at > ?"
            params.append(int(time.time()))
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

def get_expired_instances_for_user(user_id):
    now = int(time.time())
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM instances WHERE user_id = ? AND expires_at <= ? ORDER BY created_at DESC",
            (user_id, now)
        ).fetchall()
    return [dict(r) for r in rows]

def delete_instance_by_uuid(instance_uuid):
    with get_db() as conn:
        row = conn.execute("SELECT directory FROM instances WHERE instance_uuid = ?", (instance_uuid,)).fetchone()
        if row:
            shutil.rmtree(row["directory"], ignore_errors=True)
        conn.execute("DELETE FROM instances WHERE instance_uuid = ?", (instance_uuid,))
        conn.commit()

def count_user_active_servers(user_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM instances WHERE user_id = ? AND expires_at > ?",
            (user_id, int(time.time()))
        ).fetchone()
    return row["cnt"] if row else 0

# ---------- File Logging ----------
def log_file_upload(instance_uuid, filename, filepath, size):
    inst = get_instance_by_uuid(instance_uuid)
    if inst:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO files (instance_id, filename, filepath, size, uploaded_at) VALUES (?, ?, ?, ?, ?)",
                (inst["id"], filename, filepath, size, int(time.time()))
            )
            conn.commit()

# ---------- Users ----------
def update_user(user_id, first_name, username):
    with get_db() as conn:
        now = int(time.time())
        conn.execute("""
            INSERT INTO users (user_id, first_name, username, created_at, last_interaction, blocked)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(user_id) DO UPDATE SET
                first_name = excluded.first_name,
                username = excluded.username,
                last_interaction = excluded.last_interaction
        """, (user_id, first_name, username, now, now))
        conn.commit()

def get_user(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else None

def is_user_blocked(user_id):
    user = get_user(user_id)
    return user and user.get("blocked", 0) == 1

def block_user(user_id):
    with get_db() as conn:
        conn.execute("UPDATE users SET blocked = 1 WHERE user_id = ?", (user_id,))
        conn.commit()

def unblock_user(user_id):
    with get_db() as conn:
        conn.execute("UPDATE users SET blocked = 0 WHERE user_id = ?", (user_id,))
        conn.commit()

def get_all_users(limit=100):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY last_interaction DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

# ---------- Logging ----------
def log_action(action, user_id=None, details=None):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (timestamp, action, user_id, details) VALUES (?, ?, ?, ?)",
            (int(time.time()), action, user_id, details)
        )
        conn.commit()

# ---------- Statistics ----------
def get_stats():
    with get_db() as conn:
        total_keys = conn.execute("SELECT COUNT(*) FROM core_keys").fetchone()[0]
        active_keys = conn.execute("SELECT COUNT(*) FROM core_keys WHERE is_active=1").fetchone()[0]
        total_instances = conn.execute("SELECT COUNT(*) FROM instances").fetchone()[0]
        active_instances = conn.execute("SELECT COUNT(*) FROM instances WHERE expires_at > ?", (int(time.time()),)).fetchone()[0]
        expired_instances = conn.execute("SELECT COUNT(*) FROM instances WHERE expires_at <= ?", (int(time.time()),)).fetchone()[0]
        total_users = conn.execute("SELECT COUNT(DISTINCT user_id) FROM users").fetchone()[0]
        blocked_users = conn.execute("SELECT COUNT(*) FROM users WHERE blocked=1").fetchone()[0]
        total_files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    return {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "total_instances": total_instances,
        "active_instances": active_instances,
        "expired_instances": expired_instances,
        "total_users": total_users,
        "blocked_users": blocked_users,
        "total_files": total_files,
    }

# ==================== Flask অ্যাপ ====================

app = Flask(__name__)
app.secret_key = INSTANCE_SECRET

# ---------- লগইন পেজ (HTML) ----------
LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS Login - Bangladesh Edition</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',sans-serif; }
        body { background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); height:100vh; display:flex; justify-content:center; align-items:center; }
        .login-container { background:white; border-radius:10px; box-shadow:0 14px 28px rgba(0,0,0,0.25),0 10px 10px rgba(0,0,0,0.22); width:400px; padding:40px; }
        h2 { text-align:center; color:#333; margin-bottom:30px; font-weight:500; }
        .flag { text-align:center; margin-bottom:20px; font-size:48px; }
        .input-group { margin-bottom:20px; }
        label { display:block; margin-bottom:8px; color:#555; font-size:14px; }
        input[type="password"] { width:100%; padding:12px 15px; border:1px solid #ddd; border-radius:5px; font-size:16px; transition:0.3s; }
        input[type="password"]:focus { border-color:#667eea; outline:none; box-shadow:0 0 8px rgba(102,126,234,0.3); }
        button { width:100%; padding:12px; background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); border:none; border-radius:5px; color:white; font-size:16px; font-weight:600; cursor:pointer; transition:0.3s; }
        button:hover { transform:translateY(-2px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }
        .info { margin-top:20px; text-align:center; font-size:14px; color:#777; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="flag">🇧🇩</div>
        <h2>VPS File Server Login</h2>
        <form method="post">
            <div class="input-group">
                <label for="password">🔑 Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your VPS password" required autofocus>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="info">
            <p>Secure file server provided by<br><strong>Telegram VPS Bot – Bangladesh Edition</strong></p>
        </div>
    </div>
</body>
</html>"""

# ---------- ভিপিএস ফাইল ম্যানেজার রুট ----------
@app.route('/vps/<instance_uuid>/', methods=['GET', 'POST'])
@app.route('/vps/<instance_uuid>', methods=['GET', 'POST'])
def vps_root(instance_uuid):
    # ইন্সট্যান্স চেক
    inst = get_instance_by_uuid(instance_uuid)
    if not inst:
        return "VPS not found", 404
    if inst['expires_at'] < int(time.time()):
        return "<h2>This VPS has expired.</h2><p>Renew with a new Core Key via Telegram.</p>", 410

    # অথেনটিকেশন চেক (সেশন)
    if not session.get(f'vps_auth_{instance_uuid}'):
        if request.method == 'POST':
            password = request.form.get('password')
            if password == inst['password']:
                session[f'vps_auth_{instance_uuid}'] = True
                return redirect(request.url)
            else:
                return LOGIN_PAGE_HTML.replace('<form method="post">', '<form method="post"><p style="color:red;">Invalid password</p>')
        return LOGIN_PAGE_HTML

    # অথেনটিকেটেড – ফাইল তালিকা দেখাও
    directory = inst['directory']
    if not os.path.exists(directory):
        os.makedirs(directory)

    if request.method == 'POST':
        # ফাইল আপলোড
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = os.path.basename(file.filename)
                filepath = os.path.join(directory, filename)
                file.save(filepath)
                size = os.path.getsize(filepath)
                log_file_upload(instance_uuid, filename, filepath, size)
                return redirect(request.url)
        # ফাইল ডিলিট
        delete_file = request.form.get('delete')
        if delete_file:
            filepath = os.path.join(directory, delete_file)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                os.remove(filepath)
            return redirect(request.url)

    # ফাইল তালিকা জেনারেট
    files = []
    if os.path.exists(directory):
        for f in os.listdir(directory):
            fullpath = os.path.join(directory, f)
            if os.path.isfile(fullpath):
                size = os.path.getsize(fullpath)
                files.append({
                    'name': f,
                    'size': size,
                    'size_str': f"{size} B" if size < 1024 else f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                })
    files.sort(key=lambda x: x['name'].lower())

    # HTML তৈরি
    base_url = PUBLIC_URL or request.host_url.rstrip('/')
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VPS File Manager</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px; }}
        h1 {{ margin-top: 0; color: #2c3e50; }}
        .info {{ background: #e8f4fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; background: #34495e; color: white; padding: 12px; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f1f1f1; }}
        .btn {{ display: inline-block; padding: 8px 16px; background: #3498db; color: white; text-decoration: none; border-radius: 4px; border: none; cursor: pointer; }}
        .btn-danger {{ background: #e74c3c; }}
        .btn:hover {{ opacity: 0.9; }}
        .upload-form {{ margin: 20px 0; padding: 20px; background: #ecf0f1; border-radius: 5px; }}
        input[type=file] {{ padding: 10px; }}
        .logout {{ float: right; }}
        .footer {{ margin-top: 30px; font-size: 0.9em; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 VPS File Server 
            <a href="{url_for('vps_logout', instance_uuid=instance_uuid)}" class="btn btn-danger logout">Logout</a>
        </h1>
        <div class="info">
            <strong>Access URL:</strong> <code>{base_url}/vps/{instance_uuid}/</code><br>
            <strong>Expires:</strong> {datetime.fromtimestamp(inst['expires_at']).strftime('%Y-%m-%d %H:%M')}
        </div>
        <div class="upload-form">
            <h3>📤 Upload File</h3>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit" class="btn">Upload</button>
            </form>
        </div>
        <h3>📄 Files</h3>
        <table>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Actions</th>
            </tr>"""
    for f in files:
        html += f"""
            <tr>
                <td><a href="{url_for('vps_download', instance_uuid=instance_uuid, filename=f['name'])}">{html.escape(f['name'])}</a></td>
                <td>{f['size_str']}</td>
                <td>
                    <a href="{url_for('vps_download', instance_uuid=instance_uuid, filename=f['name'])}" class="btn" download>Download</a>
                    <form method="post" style="display:inline;">
                        <input type="hidden" name="delete" value="{f['name']}">
                        <button type="submit" class="btn btn-danger" onclick="return confirm('Delete {f['name']}?')">Delete</button>
                    </form>
                </td>
            </tr>"""
    html += """
        </table>
        <div class="footer">
            Powered by Telegram VPS Bot – Bangladesh Edition
        </div>
    </div>
</body>
</html>"""
    return html

@app.route('/vps/<instance_uuid>/logout')
def vps_logout(instance_uuid):
    session.pop(f'vps_auth_{instance_uuid}', None)
    return redirect(url_for('vps_root', instance_uuid=instance_uuid))

@app.route('/vps/<instance_uuid>/download/<path:filename>')
def vps_download(instance_uuid, filename):
    inst = get_instance_by_uuid(instance_uuid)
    if not inst or not session.get(f'vps_auth_{instance_uuid}'):
        return redirect(url_for('vps_root', instance_uuid=instance_uuid))
    directory = inst['directory']
    return send_from_directory(directory, filename, as_attachment=True)

# ---------- টেলিগ্রাম ওয়েবহুক ----------
bot = telebot.TeleBot(BOT_TOKEN, threaded=False)

@app.route('/webhook', methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_data().decode('utf-8')
        update = Update.de_json(json_string)
        bot.process_new_updates([update])
        return '', 200
    return '', 403

def set_webhook():
    if not PUBLIC_URL:
        logger.error("PUBLIC_URL not set. Cannot set webhook.")
        return False
    webhook_url = f"{PUBLIC_URL}/webhook"
    bot.remove_webhook()
    time.sleep(0.5)
    bot.set_webhook(url=webhook_url)
    logger.info(f"Webhook set to {webhook_url}")
    return True

# ---------- টেলিগ্রাম হ্যান্ডলার ----------
def main_menu(user_id):
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("🖥 My VPS"),
        KeyboardButton("🔑 Redeem Key")
    )
    if user_id == OWNER_ID:
        markup.add(KeyboardButton("⚙️ Admin Panel"))
    markup.add(KeyboardButton("📞 Help"))
    return markup

def admin_menu():
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("🔐 Generate Key"),
        KeyboardButton("🗝 List Keys"),
        KeyboardButton("📋 All Instances"),
        KeyboardButton("👥 User Management"),
        KeyboardButton("📊 Detailed Stats"),
        KeyboardButton("🔙 Back")
    )
    return markup

def back_menu():
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🔙 Back"))
    return markup

@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ Your account is blocked. Contact admin.")
        return
    update_user(user_id, message.from_user.first_name, message.from_user.username)
    bot.send_message(
        message.chat.id,
        f"🚀 Welcome to **VPS Bot** (Instance: {INSTANCE_ID})\n"
        f"🌍 Your VPS will be accessible at:\n"
        f"`{PUBLIC_URL or 'https://your-domain.com'}/vps/<UUID>/`\n\n"
        "Redeem a Core Key to get your own private file server.\n"
        "Use the menu below.",
        reply_markup=main_menu(user_id),
        parse_mode="Markdown"
    )
    log_action("/start", user_id)

@bot.message_handler(func=lambda m: m.text == "🔙 Back")
def back_handler(message):
    user_id = message.from_user.id
    bot.send_message(message.chat.id, "Main menu:", reply_markup=main_menu(user_id))

@bot.message_handler(func=lambda m: m.text == "📞 Help")
def help_handler(message):
    text = (
        "📘 **How to use**\n\n"
        "• **Redeem Key** – Enter a Core Key to create or renew a VPS.\n"
        "• **My VPS** – View and manage your active servers.\n"
        "• Each VPS is a **private file server** protected by password.\n"
        "• **Access URL**: `{PUBLIC_URL}/vps/<UUID>/`\n"
        "• **Login**: Use the password on the login page.\n"
        "• Upload/download/delete files via web interface.\n"
        "• Servers auto‑expire after the key's duration.\n"
        "• **Renewal**: If you have an expired server, redeeming a key will ask if you want to renew it.\n\n"
        "Admin commands are shown if you are the owner."
    ).format(PUBLIC_URL=PUBLIC_URL or 'https://your-domain.com')
    bot.send_message(message.chat.id, text, parse_mode="Markdown")

@bot.message_handler(func=lambda m: m.text == "🔑 Redeem Key")
def redeem_prompt(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ You are blocked. Contact admin.", reply_markup=main_menu(user_id))
        return
    msg = bot.send_message(message.chat.id, "Please enter your Core Key:", reply_markup=back_menu())
    bot.register_next_step_handler(msg, process_redeem)

def process_redeem(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    if message.text == "🔙 Back":
        bot.send_message(message.chat.id, "Cancelled.", reply_markup=main_menu(user_id))
        return
    key_str = message.text.strip()
    core_key = get_core_key(key_str)
    if not core_key:
        bot.send_message(message.chat.id, "❌ Invalid or expired Core Key.", reply_markup=main_menu(user_id))
        return
    expired = get_expired_instances_for_user(user_id)
    if expired:
        markup = InlineKeyboardMarkup()
        for inst in expired[:5]:
            expires = datetime.fromtimestamp(inst['expires_at']).strftime("%Y-%m-%d")
            btn_text = f"Renew VPS ({inst['instance_uuid'][:8]} expired {expires})"
            markup.add(InlineKeyboardButton(btn_text, callback_data=f"renew:{inst['instance_uuid']}:{key_str}"))
        markup.add(InlineKeyboardButton("➕ Create New Server", callback_data=f"new:{key_str}"))
        markup.add(InlineKeyboardButton("❌ Cancel", callback_data="cancel_renew"))
        bot.send_message(
            message.chat.id,
            "You have expired VPS. Choose one to renew, or create a new one:",
            reply_markup=markup
        )
        return
    create_new_vps(user_id, core_key, message.chat.id)

def create_new_vps(user_id, core_key, chat_id):
    if is_user_blocked(user_id):
        bot.send_message(chat_id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    active = count_user_active_servers(user_id)
    if active >= core_key['max_servers']:
        bot.send_message(
            chat_id,
            f"❌ You already have {active} active server(s). This key allows max {core_key['max_servers']}.",
            reply_markup=main_menu(user_id)
        )
        return
    try:
        instance_id, instance_uuid, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days']
        )
        increment_key_usage(core_key['id'])
        bot.send_message(
            chat_id,
            f"✅ **VPS Created Successfully!**\n\n"
            f"🌍 **Public URL:** `{PUBLIC_URL}/vps/{instance_uuid}/`\n"
            f"🔑 **Password:** `{password}`\n"
            f"📁 **Root Directory:** `{directory}`\n"
            f"⏳ **Expires:** {datetime.fromtimestamp(int(time.time()) + core_key['duration_days']*86400).strftime('%Y-%m-%d %H:%M')}\n\n"
            f"Use the password to login via browser.",
            parse_mode="Markdown",
            reply_markup=main_menu(user_id)
        )
        log_action("redeem_key_new", user_id, f"key={core_key['key']}, instance={instance_uuid}")
    except Exception as e:
        bot.send_message(chat_id, f"❌ Error creating VPS: {e}", reply_markup=main_menu(user_id))

@bot.callback_query_handler(func=lambda call: call.data.startswith("renew:"))
def renew_callback(call):
    _, instance_uuid, key_str = call.data.split(":", 2)
    user_id = call.from_user.id
    core_key = get_core_key(key_str)
    if not core_key:
        bot.answer_callback_query(call.id, "Key invalid.", show_alert=True)
        return
    inst = get_instance_by_uuid(instance_uuid)
    if not inst or inst['user_id'] != user_id:
        bot.answer_callback_query(call.id, "Not your instance.", show_alert=True)
        return
    try:
        instance_id, _, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days'], renewed_instance_id=inst['id']
        )
        increment_key_usage(core_key['id'])
        bot.edit_message_text(
            f"✅ **VPS Renewed Successfully!**\n\n"
            f"🌍 **Public URL:** `{PUBLIC_URL}/vps/{instance_uuid}/`\n"
            f"🔑 **Password:** `{password}` (unchanged)\n"
            f"⏳ **New Expiry:** {datetime.fromtimestamp(inst['expires_at']).strftime('%Y-%m-%d %H:%M')}",
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown"
        )
        log_action("renew_instance", user_id, f"key={core_key['key']}, instance={instance_uuid}")
    except Exception as e:
        bot.edit_message_text(f"❌ Error: {e}", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("new:"))
def new_callback(call):
    _, key_str = call.data.split(":")
    user_id = call.from_user.id
    core_key = get_core_key(key_str)
    if not core_key:
        bot.answer_callback_query(call.id, "Key invalid.", show_alert=True)
        return
    bot.delete_message(call.message.chat.id, call.message.message_id)
    create_new_vps(user_id, core_key, call.message.chat.id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "cancel_renew")
def cancel_renew(call):
    bot.edit_message_text("Cancelled.", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: m.text == "🖥 My VPS")
def my_vps(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    instances = get_user_instances(user_id, include_expired=False)
    if not instances:
        bot.send_message(message.chat.id, "You have no active VPS instances.", reply_markup=main_menu(user_id))
        return
    markup = InlineKeyboardMarkup()
    for inst in instances:
        expires = datetime.fromtimestamp(inst['expires_at']).strftime("%m-%d %H:%M")
        btn_text = f"VPS {inst['instance_uuid'][:8]} (exp {expires})"
        markup.add(InlineKeyboardButton(btn_text, callback_data=f"vps_info:{inst['instance_uuid']}"))
    bot.send_message(message.chat.id, "Your VPS instances:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("vps_info:"))
def vps_info(call):
    instance_uuid = call.data.split(":", 1)[1]
    inst = get_instance_by_uuid(instance_uuid)
    if not inst:
        bot.answer_callback_query(call.id, "Instance not found.")
        return
    user_id = call.from_user.id
    if inst['user_id'] != user_id and user_id != OWNER_ID:
        bot.answer_callback_query(call.id, "Access denied.")
        return
    expires = datetime.fromtimestamp(inst['expires_at']).strftime("%Y-%m-%d %H:%M")
    text = (
        f"**VPS Details**\n"
        f"🌍 URL: `{PUBLIC_URL}/vps/{instance_uuid}/`\n"
        f"🔑 Password: `{inst['password']}`\n"
        f"⏳ Expires: {expires}\n"
    )
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🔗 Open VPS", url=f"{PUBLIC_URL}/vps/{instance_uuid}/"))
    markup.add(InlineKeyboardButton("🗑 Delete", callback_data=f"delete_vps:{instance_uuid}"))
    markup.add(InlineKeyboardButton("🔙 Back", callback_data="back_to_myvps"))
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode="Markdown",
        reply_markup=markup
    )
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("delete_vps:"))
def delete_vps_callback(call):
    instance_uuid = call.data.split(":", 1)[1]
    inst = get_instance_by_uuid(instance_uuid)
    if not inst:
        bot.answer_callback_query(call.id, "Not found.")
        return
    if inst['user_id'] != call.from_user.id and call.from_user.id != OWNER_ID:
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    delete_instance_by_uuid(instance_uuid)
    bot.answer_callback_query(call.id, "VPS deleted.", show_alert=True)
    bot.delete_message(call.message.chat.id, call.message.message_id)
    bot.send_message(call.message.chat.id, "Instance removed.", reply_markup=main_menu(call.from_user.id))

@bot.callback_query_handler(func=lambda call: call.data == "back_to_myvps")
def back_to_myvps(call):
    my_vps(call.message)

# ---------- অ্যাডমিন হ্যান্ডলার ----------
@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "⚙️ Admin Panel")
def admin_panel(message):
    bot.send_message(message.chat.id, "🛠 Admin Panel", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "🔐 Generate Key")
def gen_key_prompt(message):
    msg = bot.send_message(
        message.chat.id,
        "Enter duration in days and max servers, separated by space.\n"
        "Example: `30 2`",
        parse_mode="Markdown",
        reply_markup=back_menu()
    )
    bot.register_next_step_handler(msg, process_gen_key)

def process_gen_key(message):
    if message.text == "🔙 Back":
        bot.send_message(message.chat.id, "Cancelled.", reply_markup=admin_menu())
        return
    try:
        days, max_servers = map(int, message.text.split())
        if days <= 0 or max_servers <= 0:
            raise ValueError
        key = generate_core_key(days, max_servers, message.from_user.id)
        bot.send_message(
            message.chat.id,
            f"✅ Core Key generated:\n`{key}`\n\nDuration: {days} days\nMax servers: {max_servers}",
            parse_mode="Markdown",
            reply_markup=admin_menu()
        )
        log_action("generate_key", message.from_user.id, f"key={key}")
    except:
        bot.send_message(message.chat.id, "Invalid input. Use: days max_servers", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "🗝 List Keys")
def list_keys(message):
    keys = list_core_keys(active_only=True)
    if not keys:
        bot.send_message(message.chat.id, "No active keys.", reply_markup=admin_menu())
        return
    text = "🔑 **Active Core Keys**\n\n"
    for k in keys:
        text += f"`{k['key']}` – {k['duration_days']}d, used {k['used_count']}/{k['max_servers']}\n"
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "📋 All Instances")
def all_instances(message):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM instances ORDER BY created_at DESC LIMIT 20").fetchall()
    if not rows:
        bot.send_message(message.chat.id, "No instances.", reply_markup=admin_menu())
        return
    text = "📋 **Recent Instances**\n\n"
    for r in rows:
        expires = datetime.fromtimestamp(r['expires_at']).strftime("%Y-%m-%d")
        text += f"• User `{r['user_id']}` – UUID `{r['instance_uuid'][:8]}` – expires {expires}\n"
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "👥 User Management")
def user_management(message):
    users = get_all_users(limit=10)
    if not users:
        bot.send_message(message.chat.id, "No users.", reply_markup=admin_menu())
        return
    text = "👥 **Recent Users**\n\n"
    markup = InlineKeyboardMarkup()
    for u in users:
        blocked = "🔴 Blocked" if u['blocked'] else "🟢 Active"
        btn_text = f"{u['user_id']} - {u.get('first_name','')[:10]} ({blocked})"
        markup.add(InlineKeyboardButton(btn_text, callback_data=f"admin_user:{u['user_id']}"))
    bot.send_message(message.chat.id, text, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.from_user.id == OWNER_ID and call.data.startswith("admin_user:"))
def admin_user_detail(call):
    user_id = int(call.data.split(":")[1])
    user = get_user(user_id)
    if not user:
        bot.answer_callback_query(call.id, "User not found.")
        return
    instances = get_user_instances(user_id, include_expired=True)
    active = sum(1 for i in instances if i['expires_at'] > time.time())
    text = (
        f"👤 **User Details**\n"
        f"ID: `{user_id}`\n"
        f"Name: {user.get('first_name','')}\n"
        f"Username: @{user.get('username','')}\n"
        f"Joined: {datetime.fromtimestamp(user['created_at']).strftime('%Y-%m-%d')}\n"
        f"Last: {datetime.fromtimestamp(user['last_interaction']).strftime('%Y-%m-%d %H:%M')}\n"
        f"Blocked: {'Yes' if user['blocked'] else 'No'}\n"
        f"Total VPS: {len(instances)}\n"
        f"Active: {active}\n"
    )
    markup = InlineKeyboardMarkup()
    if user['blocked']:
        markup.add(InlineKeyboardButton("✅ Unblock", callback_data=f"admin_unblock:{user_id}"))
    else:
        markup.add(InlineKeyboardButton("❌ Block", callback_data=f"admin_block:{user_id}"))
    markup.add(InlineKeyboardButton("🔙 Back", callback_data="admin_back_users"))
    bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=markup)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.from_user.id == OWNER_ID and call.data.startswith("admin_block:"))
def admin_block(call):
    user_id = int(call.data.split(":")[1])
    block_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} blocked.", show_alert=True)
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: call.from_user.id == OWNER_ID and call.data.startswith("admin_unblock:"))
def admin_unblock(call):
    user_id = int(call.data.split(":")[1])
    unblock_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} unblocked.", show_alert=True)
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: call.from_user.id == OWNER_ID and call.data == "admin_back_users")
def admin_back_users(call):
    user_management(call.message)

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "📊 Detailed Stats")
def detailed_stats(message):
    stats = get_stats()
    text = (
        f"📊 **System Statistics**\n\n"
        f"🗝 **Keys**\n"
        f"• Total: {stats['total_keys']}\n"
        f"• Active: {stats['active_keys']}\n\n"
        f"🖥 **Instances**\n"
        f"• Total: {stats['total_instances']}\n"
        f"• Active: {stats['active_instances']}\n"
        f"• Expired: {stats['expired_instances']}\n\n"
        f"👥 **Users**\n"
        f"• Total: {stats['total_users']}\n"
        f"• Blocked: {stats['blocked_users']}\n\n"
        f"📁 **Files**\n"
        f"• Total uploaded: {stats['total_files']}\n"
    )
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.from_user.id == OWNER_ID and m.text == "🔙 Back")
def admin_back(message):
    user_id = message.from_user.id
    bot.send_message(message.chat.id, "Main menu:", reply_markup=main_menu(user_id))

@bot.message_handler(func=lambda m: True)
def fallback(message):
    user_id = message.from_user.id
    bot.send_message(message.chat.id, "Please use the menu buttons.", reply_markup=main_menu(user_id))

# ---------- ফ্লাস্ক অ্যাডমিন প্যানেল (ঐচ্ছিক) ----------
@app.route('/admin/dashboard')
def admin_dashboard():
    # সরলীকৃত – প্রোডাকশনে এডমিন লগিন যুক্ত করবেন
    return "Admin Dashboard – under construction"

# ==================== মেইন ====================

def main():
    init_db()
    # ওয়েবহুক সেট
    if PUBLIC_URL:
        set_webhook()
    else:
        logger.warning("PUBLIC_URL not set. Webhook not configured.")
    # ফ্লাস্ক চালু
    logger.info(f"Starting Flask on 0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
