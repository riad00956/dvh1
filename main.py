#!/usr/bin/env python3
"""
Telegram Personal VPS Bot – Premium Edition
- Multi‑user, multi‑server with key‑based expiry
- Admin panel for user/instance/key management
- Automatic server renewal & port range configuration
- Clean menu‑based Telegram interface
"""

import os
import sys
import json
import uuid
import socket
import logging
import threading
import sqlite3
import random
import string
import time
import signal
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, unquote
import base64

# Third‑party
from dotenv import load_dotenv, set_key
import telebot
from telebot.types import (
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton
)
from flask import Flask, request, session, redirect, url_for, send_file, abort, render_template_string

# Optional monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ==================== CONFIGURATION ====================

ENV_FILE = ".env"
load_dotenv(ENV_FILE)

# Provided credentials (used as fallback if .env is missing)
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

# Flask admin port
ADMIN_PORT = int(os.getenv("ADMIN_PORT", 5000))

# Default port range (can be changed via admin panel)
DEFAULT_PORT_MIN = 1999
DEFAULT_PORT_MAX = 9999
PORT_MIN = int(os.getenv("PORT_MIN", DEFAULT_PORT_MIN))
PORT_MAX = int(os.getenv("PORT_MAX", DEFAULT_PORT_MAX))

# Database
DB_FILE = f"instance_{INSTANCE_ID}.db"

# ==================== LOGGING ====================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("VPSBot")

# ==================== DATABASE LAYER ====================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # Settings (key‑value)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # Insert default port range if not exists
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('port_min', ?)", (str(PORT_MIN),))
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('port_max', ?)", (str(PORT_MAX),))

        # Core keys
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
        # User instances
        conn.execute("""
            CREATE TABLE IF NOT EXISTS instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_uuid TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                port INTEGER UNIQUE NOT NULL,
                password TEXT NOT NULL,
                directory TEXT NOT NULL,
                pid INTEGER,
                status TEXT DEFAULT 'stopped',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                core_key_id INTEGER,
                renewed_from INTEGER,  -- if this instance is a renewal, store original instance id
                FOREIGN KEY(core_key_id) REFERENCES core_keys(id)
            )
        """)
        # Telegram users
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
        # Logs
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

# ---------- Settings ----------
def get_setting(key, default=None):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

def set_setting(key, value):
    with get_db() as conn:
        conn.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()

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

def deactivate_core_key(key_id):
    with get_db() as conn:
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
def get_available_port():
    """Return a free port within the current range."""
    port_min = int(get_setting("port_min", PORT_MIN))
    port_max = int(get_setting("port_max", PORT_MAX))
    used_ports = set()
    with get_db() as conn:
        used = conn.execute("SELECT port FROM instances").fetchall()
        used_ports = {r["port"] for r in used}
    for port in range(port_min, port_max + 1):
        if port not in used_ports and is_port_available(port):
            return port
    raise RuntimeError(f"No free ports in range {port_min}-{port_max}")

def create_instance(user_id, core_key_id, duration_days, renewed_instance_id=None):
    """Create a new instance or renew an existing one."""
    if renewed_instance_id:
        # Renew existing instance
        with get_db() as conn:
            inst = conn.execute("SELECT * FROM instances WHERE id = ?", (renewed_instance_id,)).fetchone()
            if not inst:
                raise ValueError("Instance not found")
            # Update expiry and status
            new_expires = int((datetime.now() + timedelta(days=duration_days)).timestamp())
            conn.execute(
                "UPDATE instances SET expires_at = ?, status = 'stopped', core_key_id = ? WHERE id = ?",
                (new_expires, core_key_id, renewed_instance_id)
            )
            conn.commit()
            return renewed_instance_id, inst["port"], inst["password"], inst["directory"]
    else:
        # Create brand new instance
        port = get_available_port()
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        instance_uuid = str(uuid.uuid4())[:12]
        directory = f"instances/{instance_uuid}"
        os.makedirs(directory, exist_ok=True)

        created_at = int(time.time())
        expires_at = int((datetime.now() + timedelta(days=duration_days)).timestamp())

        with get_db() as conn:
            conn.execute("""
                INSERT INTO instances
                (instance_uuid, user_id, port, password, directory, created_at, expires_at, core_key_id, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (instance_uuid, user_id, port, password, directory, created_at, expires_at, core_key_id, 'stopped'))
            conn.commit()
            instance_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return instance_id, port, password, directory

def get_instance(instance_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM instances WHERE id = ?", (instance_id,)).fetchone()
    return dict(row) if row else None

def get_user_instances(user_id, active_only=False, include_expired=False):
    with get_db() as conn:
        query = "SELECT * FROM instances WHERE user_id = ?"
        params = [user_id]
        if active_only:
            query += " AND status = 'running' AND expires_at > ?"
            params.append(int(time.time()))
        if not include_expired:
            query += " AND expires_at > ?"
            params.append(int(time.time()))
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

def get_all_instances(limit=50):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM instances ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def update_instance_status(instance_id, status, pid=None):
    with get_db() as conn:
        if pid is not None:
            conn.execute("UPDATE instances SET status = ?, pid = ? WHERE id = ?", (status, pid, instance_id))
        else:
            conn.execute("UPDATE instances SET status = ? WHERE id = ?", (status, instance_id))
        conn.commit()

def delete_instance(instance_id):
    stop_file_server(instance_id)
    with get_db() as conn:
        row = conn.execute("SELECT directory FROM instances WHERE id = ?", (instance_id,)).fetchone()
        if row:
            import shutil
            shutil.rmtree(row["directory"], ignore_errors=True)
        conn.execute("DELETE FROM instances WHERE id = ?", (instance_id,))
        conn.commit()

def count_user_active_servers(user_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM instances WHERE user_id = ? AND status = 'running' AND expires_at > ?",
            (user_id, int(time.time()))
        ).fetchone()
    return row["cnt"] if row else 0

def get_expired_instances_for_user(user_id):
    """Return instances that have expired and are not running."""
    now = int(time.time())
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM instances WHERE user_id = ? AND expires_at <= ? AND status != 'running' ORDER BY created_at DESC",
            (user_id, now)
        ).fetchall()
    return [dict(r) for r in rows]

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
    # Stop all running instances
    for inst in get_user_instances(user_id, active_only=True):
        stop_file_server(inst["id"])

def unblock_user(user_id):
    with get_db() as conn:
        conn.execute("UPDATE users SET blocked = 0 WHERE user_id = ?", (user_id,))
        conn.commit()

def get_all_users(limit=50):
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
        running_instances = conn.execute("SELECT COUNT(*) FROM instances WHERE status='running'").fetchone()[0]
        expired_instances = conn.execute("SELECT COUNT(*) FROM instances WHERE expires_at <= ?", (int(time.time()),)).fetchone()[0]
        total_users = conn.execute("SELECT COUNT(DISTINCT user_id) FROM users").fetchone()[0]
        blocked_users = conn.execute("SELECT COUNT(*) FROM users WHERE blocked=1").fetchone()[0]
    stats = {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "total_instances": total_instances,
        "running_instances": running_instances,
        "expired_instances": expired_instances,
        "total_users": total_users,
        "blocked_users": blocked_users,
    }
    if PSUTIL_AVAILABLE:
        stats["cpu"] = psutil.cpu_percent()
        stats["ram"] = psutil.virtual_memory().percent
        stats["disk"] = psutil.disk_usage('/').percent
    return stats

# ==================== UTILITY FUNCTIONS ====================

def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except socket.error:
            return False

def is_owner(user_id):
    return user_id == OWNER_ID

# ==================== FILE SERVER ====================

class FileServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, password=None, **kwargs):
        self.server_password = password
        super().__init__(*args, directory=directory, **kwargs)

    def authenticate(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="VPS"')
            self.end_headers()
            return False
        auth_type, credentials = auth_header.split()
        if auth_type.lower() != 'basic':
            return False
        decoded = base64.b64decode(credentials).decode('utf-8')
        _, password = decoded.split(':', 1)
        return password == self.server_password

    def send_head(self):
        if not self.authenticate():
            return None
        return super().send_head()

    def do_GET(self):
        if not self.authenticate():
            return
        super().do_GET()

    def do_POST(self):
        if not self.authenticate():
            return
        content_length = int(self.headers.get('Content-Length', 0))
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' in content_type:
            import cgi
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            file_item = form['file']
            if file_item.filename:
                filename = os.path.basename(file_item.filename)
                filepath = os.path.join(self.directory, filename)
                with open(filepath, 'wb') as f:
                    f.write(file_item.file.read())
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Upload successful')
                return
        self.send_response(400)
        self.end_headers()
        self.wfile.write(b'No file uploaded')

    def log_message(self, format, *args):
        pass

def run_file_server(port, password, directory):
    server_address = ('127.0.0.1', port)
    handler = lambda *args, **kwargs: FileServerHandler(
        *args, directory=directory, password=password, **kwargs
    )
    httpd = HTTPServer(server_address, handler)
    httpd.serve_forever()

def start_file_server(instance_id):
    inst = get_instance(instance_id)
    if not inst:
        return False, "Instance not found"
    if is_user_blocked(inst["user_id"]):
        return False, "Your account is blocked. Contact admin."
    if inst['status'] == 'running':
        return False, "Already running"
    if not os.path.exists(inst['directory']):
        os.makedirs(inst['directory'], exist_ok=True)

    proc = subprocess.Popen(
        [sys.executable, '-c',
         f"import sys; sys.path.append('.'); from main import run_file_server; run_file_server({inst['port']}, '{inst['password']}', '{inst['directory']}')"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)
    if proc.poll() is None:
        update_instance_status(instance_id, 'running', proc.pid)
        log_action("start_instance", inst['user_id'], f"instance={instance_id}")
        return True, f"Server started on http://127.0.0.1:{inst['port']}"
    else:
        return False, "Failed to start server"

def stop_file_server(instance_id):
    inst = get_instance(instance_id)
    if not inst:
        return False, "Instance not found"
    if inst['status'] != 'running' or not inst['pid']:
        update_instance_status(instance_id, 'stopped')
        return True, "Already stopped"
    try:
        os.kill(inst['pid'], signal.SIGTERM)
        time.sleep(0.3)
        update_instance_status(instance_id, 'stopped', None)
        log_action("stop_instance", inst['user_id'], f"instance={instance_id}")
        return True, "Server stopped"
    except ProcessLookupError:
        update_instance_status(instance_id, 'stopped', None)
        return True, "Server process not found, marked stopped"
    except Exception as e:
        return False, f"Error: {e}"

def restart_file_server(instance_id):
    stop_file_server(instance_id)
    time.sleep(0.5)
    return start_file_server(instance_id)

# ==================== BACKGROUND EXPIRY CHECKER ====================

def expiry_checker():
    while True:
        try:
            now = int(time.time())
            with get_db() as conn:
                expired = conn.execute(
                    "SELECT * FROM instances WHERE expires_at <= ? AND status = 'running'",
                    (now,)
                ).fetchall()
                for inst in expired:
                    stop_file_server(inst['id'])
                    try:
                        bot.send_message(
                            inst['user_id'],
                            f"⚠️ Your VPS (port {inst['port']}) has expired and has been stopped.\n"
                            "You can renew it with a new Core Key."
                        )
                    except:
                        pass
                    log_action("auto_expire", inst['user_id'], f"instance={inst['id']}")
        except Exception as e:
            logger.error(f"Expiry checker error: {e}")
        time.sleep(60)

# ==================== TELEGRAM BOT ====================

bot = telebot.TeleBot(BOT_TOKEN, threaded=False)

# ---------- Persistent Keyboards ----------
def main_menu(user_id):
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("🖥 My VPS"),
        KeyboardButton("🔑 Redeem Key")
    )
    if is_owner(user_id):
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
        KeyboardButton("🔧 Settings"),
        KeyboardButton("📊 Detailed Stats"),
        KeyboardButton("🔙 Back")
    )
    return markup

def back_menu():
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🔙 Back"))
    return markup

# ---------- Message Editing Helper ----------
def edit_or_send(chat_id, text, reply_markup=None, parse_mode=None, message_id=None):
    if message_id:
        try:
            bot.edit_message_text(text, chat_id, message_id, reply_markup=reply_markup, parse_mode=parse_mode)
            return message_id
        except:
            pass
    msg = bot.send_message(chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
    return msg.message_id

# ---------- Handlers ----------
@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ Your account is blocked. Contact admin.")
        return
    update_user(user_id, message.from_user.first_name, message.from_user.username)
    bot.send_message(
        message.chat.id,
        f"🚀 Welcome to Personal VPS Bot (Instance: {INSTANCE_ID})\n"
        "Redeem a Core Key to get your own private file server.\n"
        "Use the menu below.",
        reply_markup=main_menu(user_id)
    )
    log_action("/start", user_id)

@bot.message_handler(func=lambda m: m.text == "🔙 Back")
def back_handler(message):
    user_id = message.from_user.id
    bot.send_message(
        message.chat.id,
        "Main menu:",
        reply_markup=main_menu(user_id)
    )

@bot.message_handler(func=lambda m: m.text == "📞 Help")
def help_handler(message):
    text = (
        "📘 **How to use**\n\n"
        "• **Redeem Key** – Enter a Core Key to create or renew a VPS.\n"
        "• **My VPS** – View and manage your active servers.\n"
        "• Each VPS is a file server with password protection.\n"
        "• Upload/download files via web browser.\n"
        "• Servers auto‑expire after the key's duration.\n"
        "• **Renewal**: If you have an expired server, redeeming a key will ask if you want to renew it.\n\n"
        "Admin commands are shown if you are the owner."
    )
    bot.send_message(message.chat.id, text, parse_mode="Markdown")

# ---------- Redeem Key (with Renewal) ----------
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

    # Check if user has any expired servers that can be renewed
    expired_instances = get_expired_instances_for_user(user_id)
    if expired_instances:
        # Offer renewal
        markup = InlineKeyboardMarkup()
        for inst in expired_instances[:5]:  # limit to 5
            expires = datetime.fromtimestamp(inst['expires_at']).strftime("%Y-%m-%d")
            btn_text = f"Renew port {inst['port']} (expired {expires})"
            markup.add(InlineKeyboardButton(btn_text, callback_data=f"renew:{inst['id']}:{key_str}"))
        markup.add(InlineKeyboardButton("➕ Create New Server", callback_data=f"new:{key_str}"))
        markup.add(InlineKeyboardButton("❌ Cancel", callback_data="cancel_renew"))
        bot.send_message(
            message.chat.id,
            "You have expired servers. Choose one to renew, or create a new one:",
            reply_markup=markup
        )
        return

    # No expired servers, proceed to create new
    create_new_server(user_id, core_key, message.chat.id)

def create_new_server(user_id, core_key, chat_id):
    # Check user not blocked
    if is_user_blocked(user_id):
        bot.send_message(chat_id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    # Check server limit for this key
    active_count = count_user_active_servers(user_id)
    if active_count >= core_key['max_servers']:
        bot.send_message(
            chat_id,
            f"❌ You already have {active_count} active server(s). "
            f"This key allows max {core_key['max_servers']}.",
            reply_markup=main_menu(user_id)
        )
        return
    try:
        instance_id, port, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days']
        )
        increment_key_usage(core_key['id'])
        success, msg_text = start_file_server(instance_id)
        if success:
            bot.send_message(
                chat_id,
                f"✅ **VPS Created Successfully!**\n\n"
                f"🌐 **Address:** `http://127.0.0.1:{port}`\n"
                f"🔑 **Password:** `{password}`\n"
                f"📁 **Root Directory:** `{directory}`\n"
                f"⏳ **Expires:** {datetime.fromtimestamp(int(time.time()) + core_key['duration_days']*86400).strftime('%Y-%m-%d %H:%M')}\n\n"
                f"Use the password to login via browser.",
                parse_mode="Markdown",
                reply_markup=main_menu(user_id)
            )
            log_action("redeem_key_new", user_id, f"key={core_key['key']}, instance={instance_id}")
        else:
            bot.send_message(chat_id, f"❌ Server created but failed to start: {msg_text}", reply_markup=main_menu(user_id))
    except Exception as e:
        bot.send_message(chat_id, f"❌ Error creating VPS: {e}", reply_markup=main_menu(user_id))

@bot.callback_query_handler(func=lambda call: call.data.startswith("renew:"))
def renew_instance_cb(call):
    _, instance_id, key_str = call.data.split(":", 2)
    instance_id = int(instance_id)
    user_id = call.from_user.id
    core_key = get_core_key(key_str)
    if not core_key:
        bot.answer_callback_query(call.id, "Key invalid or expired.", show_alert=True)
        return
    # Check ownership
    inst = get_instance(instance_id)
    if not inst or inst['user_id'] != user_id:
        bot.answer_callback_query(call.id, "Not your instance.", show_alert=True)
        return
    # Renew
    try:
        instance_id, port, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days'], renewed_instance_id=instance_id
        )
        increment_key_usage(core_key['id'])
        success, msg_text = start_file_server(instance_id)
        if success:
            bot.edit_message_text(
                f"✅ **VPS Renewed Successfully!**\n\n"
                f"🌐 **Address:** `http://127.0.0.1:{port}`\n"
                f"🔑 **Password:** `{password}` (unchanged)\n"
                f"⏳ **New Expiry:** {datetime.fromtimestamp(inst['expires_at']).strftime('%Y-%m-%d %H:%M')}\n\n"
                f"The server has been restarted.",
                call.message.chat.id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            log_action("renew_instance", user_id, f"key={core_key['key']}, instance={instance_id}")
        else:
            bot.edit_message_text(f"❌ Renewal failed: {msg_text}", call.message.chat.id, call.message.message_id)
    except Exception as e:
        bot.edit_message_text(f"❌ Error: {e}", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("new:"))
def new_instance_cb(call):
    _, key_str = call.data.split(":")
    user_id = call.from_user.id
    core_key = get_core_key(key_str)
    if not core_key:
        bot.answer_callback_query(call.id, "Key invalid.", show_alert=True)
        return
    bot.delete_message(call.message.chat.id, call.message.message_id)
    create_new_server(user_id, core_key, call.message.chat.id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "cancel_renew")
def cancel_renew_cb(call):
    bot.edit_message_text("Cancelled.", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

# ---------- My VPS ----------
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
        status = "🟢" if inst['status'] == 'running' else "🔴"
        expires = datetime.fromtimestamp(inst['expires_at']).strftime("%m-%d %H:%M")
        btn_text = f"{status} Port {inst['port']} (exp {expires})"
        markup.add(InlineKeyboardButton(btn_text, callback_data=f"manage:{inst['id']}"))
    bot.send_message(message.chat.id, "Your VPS instances:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("manage:"))
def manage_instance(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if not inst:
        bot.answer_callback_query(call.id, "Instance not found.")
        return
    user_id = call.from_user.id
    if inst['user_id'] != user_id and not is_owner(user_id):
        bot.answer_callback_query(call.id, "Access denied.")
        return

    expires_str = datetime.fromtimestamp(inst['expires_at']).strftime("%Y-%m-%d %H:%M")
    text = (
        f"**VPS Details**\n"
        f"Port: `{inst['port']}`\n"
        f"Password: `{inst['password']}`\n"
        f"Status: {'🟢 Running' if inst['status'] == 'running' else '🔴 Stopped'}\n"
        f"Expires: {expires_str}\n"
        f"Directory: `{inst['directory']}`\n"
    )
    markup = InlineKeyboardMarkup(row_width=2)
    if inst['status'] == 'running':
        markup.add(
            InlineKeyboardButton("🛑 Stop", callback_data=f"stop:{instance_id}"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"restart:{instance_id}")
        )
    else:
        # Only allow start if not expired
        if inst['expires_at'] > int(time.time()):
            markup.add(InlineKeyboardButton("▶️ Start", callback_data=f"start:{instance_id}"))
        else:
            text += "\n⚠️ This server has expired. Use a new Core Key to renew it."
    markup.add(InlineKeyboardButton("🔗 Access Link", callback_data=f"link:{instance_id}"))
    if is_owner(user_id) or inst['user_id'] == user_id:
        markup.add(InlineKeyboardButton("🗑 Delete", callback_data=f"delete:{instance_id}"))
    markup.add(InlineKeyboardButton("🔙 Back to list", callback_data="back_to_myvps"))

    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode="Markdown",
        reply_markup=markup
    )
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("start:"))
def start_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if inst['user_id'] != call.from_user.id and not is_owner(call.from_user.id):
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    success, msg = start_file_server(instance_id)
    bot.answer_callback_query(call.id, msg, show_alert=True)
    if success:
        manage_instance(call)

@bot.callback_query_handler(func=lambda call: call.data.startswith("stop:"))
def stop_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if inst['user_id'] != call.from_user.id and not is_owner(call.from_user.id):
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    success, msg = stop_file_server(instance_id)
    bot.answer_callback_query(call.id, msg, show_alert=True)
    if success:
        manage_instance(call)

@bot.callback_query_handler(func=lambda call: call.data.startswith("restart:"))
def restart_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if inst['user_id'] != call.from_user.id and not is_owner(call.from_user.id):
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    success, msg = restart_file_server(instance_id)
    bot.answer_callback_query(call.id, msg, show_alert=True)
    if success:
        manage_instance(call)

@bot.callback_query_handler(func=lambda call: call.data.startswith("link:"))
def link_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if not inst:
        bot.answer_callback_query(call.id, "Not found.")
        return
    text = f"🔗 **Access your VPS**\n\nURL: `http://127.0.0.1:{inst['port']}`\nPassword: `{inst['password']}`"
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup().add(
            InlineKeyboardButton("🔙 Back to details", callback_data=f"manage:{instance_id}")
        )
    )
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("delete:"))
def delete_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if inst['user_id'] != call.from_user.id and not is_owner(call.from_user.id):
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    delete_instance(instance_id)
    bot.answer_callback_query(call.id, "Instance deleted.", show_alert=True)
    bot.delete_message(call.message.chat.id, call.message.message_id)
    bot.send_message(call.message.chat.id, "Instance removed.", reply_markup=main_menu(call.from_user.id))

@bot.callback_query_handler(func=lambda call: call.data == "back_to_myvps")
def back_to_myvps(call):
    my_vps(call.message)  # Re‑send list

# ---------- Admin Panel ----------
@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "⚙️ Admin Panel")
def admin_panel(message):
    bot.send_message(message.chat.id, "🛠 Admin Panel", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "🔐 Generate Key")
def gen_key_prompt(message):
    msg = bot.send_message(
        message.chat.id,
        "Enter duration in days and max servers, separated by space.\n"
        "Example: `30 2`  (30 days, 2 servers per key)",
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

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "🗝 List Keys")
def list_keys(message):
    keys = list_core_keys(active_only=True)
    if not keys:
        bot.send_message(message.chat.id, "No active keys.", reply_markup=admin_menu())
        return
    text = "🔑 **Active Core Keys**\n\n"
    for k in keys:
        used = k['used_count']
        max_srv = k['max_servers']
        text += f"`{k['key']}` – {k['duration_days']}d, used {used}/{max_srv}\n"
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "📋 All Instances")
def all_instances(message):
    insts = get_all_instances(limit=20)
    if not insts:
        bot.send_message(message.chat.id, "No instances.", reply_markup=admin_menu())
        return
    text = "📋 **Recent Instances**\n\n"
    for i in insts:
        expires = datetime.fromtimestamp(i['expires_at']).strftime("%Y-%m-%d")
        status_icon = "🟢" if i['status'] == 'running' else "🔴"
        text += f"{status_icon} User `{i['user_id']}` – Port {i['port']} – expires {expires}\n"
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "👥 User Management")
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

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_user:"))
def admin_user_detail(call):
    user_id = int(call.data.split(":")[1])
    user = get_user(user_id)
    if not user:
        bot.answer_callback_query(call.id, "User not found.")
        return
    instances = get_user_instances(user_id, include_expired=True)
    active_count = sum(1 for i in instances if i['status'] == 'running' and i['expires_at'] > time.time())
    text = (
        f"👤 **User Details**\n"
        f"ID: `{user_id}`\n"
        f"Name: {user.get('first_name','')}\n"
        f"Username: @{user.get('username','')}\n"
        f"Joined: {datetime.fromtimestamp(user['created_at']).strftime('%Y-%m-%d')}\n"
        f"Last interaction: {datetime.fromtimestamp(user['last_interaction']).strftime('%Y-%m-%d %H:%M')}\n"
        f"Blocked: {'Yes' if user['blocked'] else 'No'}\n"
        f"Total servers: {len(instances)}\n"
        f"Active servers: {active_count}\n"
    )
    markup = InlineKeyboardMarkup()
    if user['blocked']:
        markup.add(InlineKeyboardButton("✅ Unblock", callback_data=f"admin_unblock:{user_id}"))
    else:
        markup.add(InlineKeyboardButton("❌ Block", callback_data=f"admin_block:{user_id}"))
    markup.add(InlineKeyboardButton("🔙 Back to users", callback_data="admin_back_users"))
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode="Markdown",
        reply_markup=markup
    )
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_block:"))
def admin_block(call):
    user_id = int(call.data.split(":")[1])
    block_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} blocked.", show_alert=True)
    # Refresh view
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_unblock:"))
def admin_unblock(call):
    user_id = int(call.data.split(":")[1])
    unblock_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} unblocked.", show_alert=True)
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: call.data == "admin_back_users")
def admin_back_users(call):
    user_management(call.message)

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "🔧 Settings")
def settings_menu(message):
    port_min = get_setting("port_min", PORT_MIN)
    port_max = get_setting("port_max", PORT_MAX)
    text = (
        f"🔧 **Current Settings**\n\n"
        f"Port range: `{port_min} – {port_max}`\n\n"
        "Use buttons below to change."
    )
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("✏️ Change Port Range", callback_data="admin_set_port"))
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == "admin_set_port")
def admin_set_port_prompt(call):
    msg = bot.send_message(
        call.message.chat.id,
        "Enter new port range (min max), e.g. `1999 9999`:\n"
        "Both numbers must be between 1024 and 65535.",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, process_set_port)

def process_set_port(message):
    try:
        min_port, max_port = map(int, message.text.split())
        if min_port < 1024 or max_port > 65535 or min_port >= max_port:
            raise ValueError
        set_setting("port_min", min_port)
        set_setting("port_max", max_port)
        # Also update .env for persistence
        set_key(ENV_FILE, "PORT_MIN", str(min_port))
        set_key(ENV_FILE, "PORT_MAX", str(max_port))
        bot.send_message(
            message.chat.id,
            f"✅ Port range updated to {min_port}-{max_port}",
            reply_markup=admin_menu()
        )
        log_action("change_port_range", message.from_user.id, f"{min_port}-{max_port}")
    except:
        bot.send_message(message.chat.id, "Invalid range. Use: min max", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "📊 Detailed Stats")
def detailed_stats(message):
    stats = get_stats()
    text = (
        f"📊 **System Statistics**\n\n"
        f"🗝 **Keys**\n"
        f"• Total: {stats['total_keys']}\n"
        f"• Active: {stats['active_keys']}\n\n"
        f"🖥 **Instances**\n"
        f"• Total: {stats['total_instances']}\n"
        f"• Running: {stats['running_instances']}\n"
        f"• Expired: {stats['expired_instances']}\n\n"
        f"👥 **Users**\n"
        f"• Total: {stats['total_users']}\n"
        f"• Blocked: {stats['blocked_users']}\n"
    )
    if PSUTIL_AVAILABLE:
        text += (
            f"\n🖥 **System Resources**\n"
            f"• CPU: {stats['cpu']}%\n"
            f"• RAM: {stats['ram']}%\n"
            f"• Disk: {stats['disk']}%\n"
        )
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

# ---------- Fallback ----------
@bot.message_handler(func=lambda m: True)
def fallback(message):
    user_id = message.from_user.id
    bot.send_message(
        message.chat.id,
        "Please use the menu buttons.",
        reply_markup=main_menu(user_id)
    )

# ==================== FLASK ADMIN WEB PANEL ====================

app = Flask(__name__)
app.secret_key = INSTANCE_SECRET

# ---------- Auth ----------
def verify_admin(core_key, instance_secret):
    return core_key == os.getenv("CORE_KEY", "CHANGE_ME") and instance_secret == INSTANCE_SECRET

@app.route('/')
def index():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        core = request.form.get('core_key')
        secret = request.form.get('instance_secret')
        if verify_admin(core, secret):
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid credentials", 403
    return '''
    <h2>Admin Login</h2>
    <form method="post">
        <label>Core Key:</label><br>
        <input type="password" name="core_key"><br>
        <label>Instance Secret:</label><br>
        <input type="password" name="instance_secret"><br><br>
        <input type="submit" value="Login">
    </form>
    '''

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = get_stats()
    port_min = get_setting("port_min", PORT_MIN)
    port_max = get_setting("port_max", PORT_MAX)
    html = f"""
    <h2>Instance {INSTANCE_ID} Dashboard</h2>
    <h3>System Overview</h3>
    <ul>
        <li>Total Keys: {stats['total_keys']}</li>
        <li>Active Keys: {stats['active_keys']}</li>
        <li>Total Instances: {stats['total_instances']}</li>
        <li>Running Instances: {stats['running_instances']}</li>
        <li>Total Users: {stats['total_users']}</li>
        <li>Blocked Users: {stats['blocked_users']}</li>
        <li>Port Range: {port_min} - {port_max}</li>
    </ul>
    <p><a href="/admin/instances">Manage Instances</a></p>
    <p><a href="/admin/users">Manage Users</a></p>
    <p><a href="/admin/keys">Core Keys</a></p>
    <p><a href="/admin/settings">Settings</a></p>
    <p><a href="/admin/export">Export Database</a></p>
    """
    return html

@app.route('/admin/instances')
@admin_required
def admin_instances():
    instances = get_all_instances(limit=100)
    html = "<h2>All Instances</h2><table border='1'><tr><th>ID</th><th>User</th><th>Port</th><th>Status</th><th>Expires</th><th>Actions</th></tr>"
    for i in instances:
        expires = datetime.fromtimestamp(i['expires_at']).strftime("%Y-%m-%d %H:%M")
        html += f"<tr><td>{i['id']}</td><td>{i['user_id']}</td><td>{i['port']}</td><td>{i['status']}</td><td>{expires}</td>"
        html += f"<td><a href='/admin/instance/{i['id']}/stop'>Stop</a> | <a href='/admin/instance/{i['id']}/start'>Start</a> | <a href='/admin/instance/{i['id']}/delete'>Delete</a></td></tr>"
    html += "</table><p><a href='/admin/dashboard'>Back</a></p>"
    return html

@app.route('/admin/instance/<int:instance_id>/<action>')
@admin_required
def admin_instance_action(instance_id, action):
    if action == 'stop':
        stop_file_server(instance_id)
    elif action == 'start':
        start_file_server(instance_id)
    elif action == 'delete':
        delete_instance(instance_id)
    return redirect(url_for('admin_instances'))

@app.route('/admin/users')
@admin_required
def admin_users():
    users = get_all_users(limit=100)
    html = "<h2>Users</h2><table border='1'><tr><th>User ID</th><th>Name</th><th>Username</th><th>Blocked</th><th>Actions</th></tr>"
    for u in users:
        html += f"<tr><td>{u['user_id']}</td><td>{u['first_name']}</td><td>{u['username']}</td><td>{u['blocked']}</td>"
        if u['blocked']:
            html += f"<td><a href='/admin/user/{u['user_id']}/unblock'>Unblock</a></td>"
        else:
            html += f"<td><a href='/admin/user/{u['user_id']}/block'>Block</a></td>"
        html += "</tr>"
    html += "</table><p><a href='/admin/dashboard'>Back</a></p>"
    return html

@app.route('/admin/user/<int:user_id>/block')
@admin_required
def admin_user_block(user_id):
    block_user(user_id)
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/unblock')
@admin_required
def admin_user_unblock(user_id):
    unblock_user(user_id)
    return redirect(url_for('admin_users'))

@app.route('/admin/keys')
@admin_required
def admin_keys():
    keys = list_core_keys(active_only=False)
    html = "<h2>Core Keys</h2><table border='1'><tr><th>Key</th><th>Duration</th><th>Max Servers</th><th>Used</th><th>Active</th><th>Created</th></tr>"
    for k in keys:
        created = datetime.fromtimestamp(k['created_at']).strftime("%Y-%m-%d")
        html += f"<tr><td>{k['key']}</td><td>{k['duration_days']}d</td><td>{k['max_servers']}</td><td>{k['used_count']}</td><td>{k['is_active']}</td><td>{created}</td></tr>"
    html += "</table><p><a href='/admin/dashboard'>Back</a></p>"
    return html

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        min_port = request.form.get('port_min')
        max_port = request.form.get('port_max')
        try:
            min_port = int(min_port)
            max_port = int(max_port)
            if 1024 <= min_port < max_port <= 65535:
                set_setting("port_min", min_port)
                set_setting("port_max", max_port)
                set_key(ENV_FILE, "PORT_MIN", str(min_port))
                set_key(ENV_FILE, "PORT_MAX", str(max_port))
                return redirect(url_for('admin_settings'))
        except:
            pass
    port_min = get_setting("port_min", PORT_MIN)
    port_max = get_setting("port_max", PORT_MAX)
    html = f"""
    <h2>Settings</h2>
    <form method="post">
        <label>Port Min:</label><br>
        <input type="number" name="port_min" value="{port_min}" min="1024" max="65535"><br>
        <label>Port Max:</label><br>
        <input type="number" name="port_max" value="{port_max}" min="1024" max="65535"><br><br>
        <input type="submit" value="Save">
    </form>
    <p><a href='/admin/dashboard'>Back</a></p>
    """
    return html

@app.route('/admin/export')
@admin_required
def admin_export():
    return send_file(DB_FILE, as_attachment=True, download_name=f"instance_{INSTANCE_ID}.db")

# ==================== MAIN ====================

def run_flask():
    logger.info(f"Starting Flask admin on http://127.0.0.1:{ADMIN_PORT}")
    app.run(host="127.0.0.1", port=ADMIN_PORT, debug=False, use_reloader=False)

def run_bot():
    logger.info("Starting Telegram bot...")
    try:
        bot.infinity_polling()
    except Exception as e:
        logger.error(f"Bot polling error: {e}")

def main():
    init_db()
    # Start expiry checker
    threading.Thread(target=expiry_checker, daemon=True).start()
    # Start bot thread
    threading.Thread(target=run_bot, daemon=True).start()
    # Run Flask in main thread
    run_flask()

if __name__ == "__main__":
    main()
