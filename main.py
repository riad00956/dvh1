#!/usr/bin/env python3
"""
Cyber 20 UN - Telegram Bot + Web IDE Engine
Run without arguments to start the bot.
Run with --web-engine flags to start a user's Web IDE.
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
import argparse
import shutil
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

# Third‑party
from dotenv import load_dotenv, set_key
import telebot
from telebot.types import (
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton
)
from flask import (
    Flask, request, session, redirect, 
    render_template, send_from_directory, jsonify
)
from flask_socketio import SocketIO, emit

# ========================
#        কনফিগারেশন
# ========================

ENV_FILE = ".env"
load_dotenv(ENV_FILE)

# টেলিগ্রাম বোট টোকেন (আপনার দেওয়া)
BOT_TOKEN = os.getenv("BOT_TOKEN", "8011804210:AAE--NiCSKKjbX4TC3nJVxuW64Fu53Ywh0w")
OWNER_ID = os.getenv("OWNER_ID")
if not OWNER_ID:
    OWNER_ID = "8373846582"
try:
    OWNER_ID = int(OWNER_ID)
except ValueError:
    logging.error("OWNER_ID must be integer")
    sys.exit(1)

# ইন্সট্যান্স আইডি
INSTANCE_ID = os.getenv("INSTANCE_ID")
if not INSTANCE_ID:
    INSTANCE_ID = str(uuid.uuid4())[:8]
    set_key(ENV_FILE, "INSTANCE_ID", INSTANCE_ID)

# পাবলিক ডোমেইন / হোস্ট (nginx সাবডোমেইন প্যাটার্নের জন্য)
BASE_DOMAIN = os.getenv("BASE_DOMAIN", "yourdomain.com")  # উদাহরণ: cyber20un.com
USE_HTTPS = os.getenv("USE_HTTPS", "true").lower() == "true"
PROTOCOL = "https" if USE_HTTPS else "http"

# ওয়েব ইঞ্জিনের পোর্ট রেঞ্জ
PORT_MIN = int(os.getenv("PORT_MIN", 20000))
PORT_MAX = int(os.getenv("PORT_MAX", 21000))

# ডাটাবেস
DB_FILE = f"instance_{INSTANCE_ID}.db"

# লগিং
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Cyber20UN")

# ========================
#        ডাটাবেস লেয়ার
# ========================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # Core Keys
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
        # User Instances (Web IDE processes)
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
                renewed_from INTEGER
            )
        """)
        # Users
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

# ---------- কোর কি ফাংশন ----------
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

# ---------- ইউজার ফাংশন ----------
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
    for inst in get_user_instances(user_id, include_expired=False):
        stop_web_engine(inst["id"])

def unblock_user(user_id):
    with get_db() as conn:
        conn.execute("UPDATE users SET blocked = 0 WHERE user_id = ?", (user_id,))
        conn.commit()

def get_all_users(limit=100):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY last_interaction DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

# ---------- ইন্সট্যান্স ম্যানেজমেন্ট ----------
def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except socket.error:
            return False

def get_available_port():
    used_ports = set()
    with get_db() as conn:
        used = conn.execute("SELECT port FROM instances").fetchall()
        used_ports = {r["port"] for r in used}
    for port in range(PORT_MIN, PORT_MAX + 1):
        if port not in used_ports and is_port_available(port):
            return port
    raise RuntimeError("No free ports available")

def create_instance(user_id, core_key_id, duration_days, renewed_instance_id=None):
    if renewed_instance_id:
        with get_db() as conn:
            inst = conn.execute("SELECT * FROM instances WHERE id = ?", (renewed_instance_id,)).fetchone()
            if not inst:
                raise ValueError("Instance not found")
            new_expires = int((datetime.now() + timedelta(days=duration_days)).timestamp())
            conn.execute(
                "UPDATE instances SET expires_at = ?, status = 'stopped', core_key_id = ? WHERE id = ?",
                (new_expires, core_key_id, renewed_instance_id)
            )
            conn.commit()
            return renewed_instance_id, inst["instance_uuid"], inst["port"], inst["password"], inst["directory"]
    else:
        port = get_available_port()
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        instance_uuid = str(uuid.uuid4())
        directory = f"web_instances/{instance_uuid}"
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
        return instance_id, instance_uuid, port, password, directory

def get_instance(instance_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM instances WHERE id = ?", (instance_id,)).fetchone()
    return dict(row) if row else None

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

def update_instance_status(instance_id, status, pid=None):
    with get_db() as conn:
        if pid is not None:
            conn.execute("UPDATE instances SET status = ?, pid = ? WHERE id = ?", (status, pid, instance_id))
        else:
            conn.execute("UPDATE instances SET status = ? WHERE id = ?", (status, instance_id))
        conn.commit()

def delete_instance(instance_id):
    stop_web_engine(instance_id)
    with get_db() as conn:
        row = conn.execute("SELECT directory FROM instances WHERE id = ?", (instance_id,)).fetchone()
        if row:
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

# ---------- ওয়েব ইঞ্জিন প্রসেস কন্ট্রোল ----------
def start_web_engine(instance_id):
    inst = get_instance(instance_id)
    if not inst:
        return False, "Instance not found"
    if is_user_blocked(inst["user_id"]):
        return False, "Your account is blocked."
    if inst['status'] == 'running':
        return False, "Already running"
    if not os.path.exists(inst['directory']):
        os.makedirs(inst['directory'], exist_ok=True)

    cmd = [
        sys.executable, __file__,
        "--web-engine",
        "--port", str(inst['port']),
        "--password", inst['password'],
        "--directory", inst['directory'],
        "--instance-uuid", inst['instance_uuid']
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)
    if proc.poll() is None:
        update_instance_status(instance_id, 'running', proc.pid)
        log_action("start_web_engine", inst['user_id'], f"instance={instance_id}, port={inst['port']}")
        subdomain = f"{inst['instance_uuid'][:8]}.{BASE_DOMAIN}"
        url = f"{PROTOCOL}://{subdomain}"
        return True, f"Web IDE started!\n🔗 {url}\n🔑 Password: `{inst['password']}`"
    else:
        return False, "Failed to start web engine"

def stop_web_engine(instance_id):
    inst = get_instance(instance_id)
    if not inst:
        return False, "Instance not found"
    if inst['status'] != 'running' or not inst['pid']:
        update_instance_status(instance_id, 'stopped')
        return True, "Already stopped"
    try:
        os.kill(inst['pid'], signal.SIGTERM)
        time.sleep(0.5)
        update_instance_status(instance_id, 'stopped', None)
        log_action("stop_web_engine", inst['user_id'], f"instance={instance_id}")
        return True, "Web IDE stopped"
    except ProcessLookupError:
        update_instance_status(instance_id, 'stopped', None)
        return True, "Process not found, marked stopped"
    except Exception as e:
        return False, f"Error: {e}"

def restart_web_engine(instance_id):
    stop_web_engine(instance_id)
    time.sleep(1)
    return start_web_engine(instance_id)

# ---------- লগিং ----------
def log_action(action, user_id=None, details=None):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (timestamp, action, user_id, details) VALUES (?, ?, ?, ?)",
            (int(time.time()), action, user_id, details)
        )
        conn.commit()

# ---------- এক্সপায়ার চেকার থ্রেড ----------
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
                    stop_web_engine(inst['id'])
                    try:
                        bot.send_message(
                            inst['user_id'],
                            f"⚠️ Your Web IDE (ID: {inst['instance_uuid'][:8]}) has expired and has been stopped.\n"
                            "You can renew it with a new Core Key."
                        )
                    except:
                        pass
                    log_action("auto_expire", inst['user_id'], f"instance={inst['id']}")
        except Exception as e:
            logger.error(f"Expiry checker error: {e}")
        time.sleep(60)

def is_owner(user_id):
    return user_id == OWNER_ID

# ========================
#      টেলিগ্রাম বট
# ========================

bot = telebot.TeleBot(BOT_TOKEN, threaded=False)

def main_menu(user_id):
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("🖥 My Web IDE"),
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
        KeyboardButton("📊 Stats"),
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
        f"🚀 Welcome to **Cyber 20 UN VPS Bot** (Instance: {INSTANCE_ID})\n"
        f"Redeem a Core Key to get your own personal Web IDE.\n"
        f"Access via browser: `https://<your-id>.{BASE_DOMAIN}`\n\n"
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
        "• **Redeem Key** – Enter a Core Key to create or renew your Web IDE.\n"
        "• **My Web IDE** – View and manage your active instances.\n"
        "• Each Web IDE is a **full Python development environment** with:\n"
        "  - File manager (upload, edit, delete)\n"
        "  - Live terminal (`pip install`, `python`)\n"
        "  - One‑click hosting (Flask apps on random ports behind subdomain)\n"
        "• **Access URL**: `https://<uuid-prefix>.{BASE_DOMAIN}`\n"
        "• **Login**: Use the password provided by the bot.\n"
        "• Servers auto‑expire after the key's duration.\n"
        "• **Renewal**: If your IDE expired, redeeming a key will ask if you want to renew it.\n\n"
        "Admin commands are shown if you are the owner."
    ).format(BASE_DOMAIN=BASE_DOMAIN)
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
            btn_text = f"Renew {inst['instance_uuid'][:8]} (expired {expires})"
            markup.add(InlineKeyboardButton(btn_text, callback_data=f"renew:{inst['id']}:{key_str}"))
        markup.add(InlineKeyboardButton("➕ Create New IDE", callback_data=f"new:{key_str}"))
        markup.add(InlineKeyboardButton("❌ Cancel", callback_data="cancel_renew"))
        bot.send_message(
            message.chat.id,
            "You have expired Web IDEs. Choose one to renew, or create a new one:",
            reply_markup=markup
        )
        return

    create_new_ide(user_id, core_key, message.chat.id)

def create_new_ide(user_id, core_key, chat_id):
    if is_user_blocked(user_id):
        bot.send_message(chat_id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    active = count_user_active_servers(user_id)
    if active >= core_key['max_servers']:
        bot.send_message(
            chat_id,
            f"❌ You already have {active} active Web IDE(s). This key allows max {core_key['max_servers']}.",
            reply_markup=main_menu(user_id)
        )
        return
    try:
        instance_id, instance_uuid, port, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days']
        )
        increment_key_usage(core_key['id'])
        success, msg = start_web_engine(instance_id)
        if success:
            bot.send_message(
                chat_id,
                f"✅ **Web IDE Created Successfully!**\n\n"
                f"🔗 **Access URL:** `{PROTOCOL}://{instance_uuid[:8]}.{BASE_DOMAIN}`\n"
                f"🔑 **Password:** `{password}`\n"
                f"⏳ **Expires:** {datetime.fromtimestamp(int(time.time()) + core_key['duration_days']*86400).strftime('%Y-%m-%d %H:%M')}\n\n"
                f"{msg}",
                parse_mode="Markdown",
                reply_markup=main_menu(user_id)
            )
            log_action("redeem_key_new", user_id, f"key={core_key['key']}, instance={instance_uuid}")
        else:
            bot.send_message(chat_id, f"❌ Web IDE created but failed to start: {msg}", reply_markup=main_menu(user_id))
    except Exception as e:
        bot.send_message(chat_id, f"❌ Error creating Web IDE: {e}", reply_markup=main_menu(user_id))

@bot.callback_query_handler(func=lambda call: call.data.startswith("renew:"))
def renew_callback(call):
    _, instance_id, key_str = call.data.split(":", 2)
    instance_id = int(instance_id)
    user_id = call.from_user.id
    core_key = get_core_key(key_str)
    if not core_key:
        bot.answer_callback_query(call.id, "Key invalid or expired.", show_alert=True)
        return
    inst = get_instance(instance_id)
    if not inst or inst['user_id'] != user_id:
        bot.answer_callback_query(call.id, "Not your instance.", show_alert=True)
        return
    try:
        instance_id, instance_uuid, port, password, directory = create_instance(
            user_id, core_key['id'], core_key['duration_days'], renewed_instance_id=instance_id
        )
        increment_key_usage(core_key['id'])
        success, msg = start_web_engine(instance_id)
        if success:
            bot.edit_message_text(
                f"✅ **Web IDE Renewed Successfully!**\n\n"
                f"🔗 **Access URL:** `{PROTOCOL}://{instance_uuid[:8]}.{BASE_DOMAIN}`\n"
                f"🔑 **Password:** `{password}` (unchanged)\n"
                f"⏳ **New Expiry:** {datetime.fromtimestamp(inst['expires_at']).strftime('%Y-%m-%d %H:%M')}\n\n"
                f"{msg}",
                call.message.chat.id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            log_action("renew_instance", user_id, f"key={core_key['key']}, instance={instance_uuid}")
        else:
            bot.edit_message_text(f"❌ Renewal failed: {msg}", call.message.chat.id, call.message.message_id)
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
    create_new_ide(user_id, core_key, call.message.chat.id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "cancel_renew")
def cancel_renew(call):
    bot.edit_message_text("Cancelled.", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: m.text == "🖥 My Web IDE")
def my_ide(message):
    user_id = message.from_user.id
    if is_user_blocked(user_id):
        bot.send_message(message.chat.id, "❌ Blocked.", reply_markup=main_menu(user_id))
        return
    instances = get_user_instances(user_id, include_expired=False)
    if not instances:
        bot.send_message(message.chat.id, "You have no active Web IDE instances.", reply_markup=main_menu(user_id))
        return
    markup = InlineKeyboardMarkup()
    for inst in instances:
        status = "🟢" if inst['status'] == 'running' else "🔴"
        expires = datetime.fromtimestamp(inst['expires_at']).strftime("%m-%d %H:%M")
        btn_text = f"{status} {inst['instance_uuid'][:8]} (exp {expires})"
        markup.add(InlineKeyboardButton(btn_text, callback_data=f"manage:{inst['id']}"))
    bot.send_message(message.chat.id, "Your Web IDE instances:", reply_markup=markup)

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
    subdomain = f"{inst['instance_uuid'][:8]}.{BASE_DOMAIN}"
    url = f"{PROTOCOL}://{subdomain}"
    text = (
        f"**Web IDE Details**\n"
        f"🔗 URL: `{url}`\n"
        f"🔑 Password: `{inst['password']}`\n"
        f"Status: {'🟢 Running' if inst['status'] == 'running' else '🔴 Stopped'}\n"
        f"⏳ Expires: {expires_str}\n"
    )
    markup = InlineKeyboardMarkup(row_width=2)
    if inst['status'] == 'running':
        markup.add(
            InlineKeyboardButton("🛑 Stop", callback_data=f"stop:{instance_id}"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"restart:{instance_id}")
        )
    else:
        if inst['expires_at'] > int(time.time()):
            markup.add(InlineKeyboardButton("▶️ Start", callback_data=f"start:{instance_id}"))
        else:
            text += "\n⚠️ This IDE has expired. Use a new Core Key to renew it."
    markup.add(InlineKeyboardButton("🔗 Open IDE", url=url))
    if is_owner(user_id) or inst['user_id'] == user_id:
        markup.add(InlineKeyboardButton("🗑 Delete", callback_data=f"delete:{instance_id}"))
    markup.add(InlineKeyboardButton("🔙 Back to list", callback_data="back_to_myide"))

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
    success, msg = start_web_engine(instance_id)
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
    success, msg = stop_web_engine(instance_id)
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
    success, msg = restart_web_engine(instance_id)
    bot.answer_callback_query(call.id, msg, show_alert=True)
    if success:
        manage_instance(call)

@bot.callback_query_handler(func=lambda call: call.data.startswith("delete:"))
def delete_instance_cb(call):
    instance_id = int(call.data.split(":")[1])
    inst = get_instance(instance_id)
    if inst['user_id'] != call.from_user.id and not is_owner(call.from_user.id):
        bot.answer_callback_query(call.id, "Not allowed.")
        return
    delete_instance(instance_id)
    bot.answer_callback_query(call.id, "Web IDE deleted.", show_alert=True)
    bot.delete_message(call.message.chat.id, call.message.message_id)
    bot.send_message(call.message.chat.id, "Instance removed.", reply_markup=main_menu(call.from_user.id))

@bot.callback_query_handler(func=lambda call: call.data == "back_to_myide")
def back_to_myide(call):
    my_ide(call.message)

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "⚙️ Admin Panel")
def admin_panel(message):
    bot.send_message(message.chat.id, "🛠 Admin Panel", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "🔐 Generate Key")
def gen_key_prompt(message):
    msg = bot.send_message(
        message.chat.id,
        "Enter duration in days and max servers, separated by space.\n"
        "Example: `30 2`  (30 days, 2 Web IDEs per key)",
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
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM instances ORDER BY created_at DESC LIMIT 20").fetchall()
    if not rows:
        bot.send_message(message.chat.id, "No instances.", reply_markup=admin_menu())
        return
    text = "📋 **Recent Instances**\n\n"
    for r in rows:
        expires = datetime.fromtimestamp(r['expires_at']).strftime("%Y-%m-%d")
        status_icon = "🟢" if r['status'] == 'running' else "🔴"
        text += f"{status_icon} User `{r['user_id']}` – UUID `{r['instance_uuid'][:8]}` – expires {expires}\n"
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

@bot.callback_query_handler(func=lambda call: is_owner(call.from_user.id) and call.data.startswith("admin_user:"))
def admin_user_detail(call):
    user_id = int(call.data.split(":")[1])
    user = get_user(user_id)
    if not user:
        bot.answer_callback_query(call.id, "User not found.")
        return
    instances = get_user_instances(user_id, include_expired=True)
    active = sum(1 for i in instances if i['expires_at'] > time.time() and i['status'] == 'running')
    text = (
        f"👤 **User Details**\n"
        f"ID: `{user_id}`\n"
        f"Name: {user.get('first_name','')}\n"
        f"Username: @{user.get('username','')}\n"
        f"Joined: {datetime.fromtimestamp(user['created_at']).strftime('%Y-%m-%d')}\n"
        f"Last: {datetime.fromtimestamp(user['last_interaction']).strftime('%Y-%m-%d %H:%M')}\n"
        f"Blocked: {'Yes' if user['blocked'] else 'No'}\n"
        f"Total IDEs: {len(instances)}\n"
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

@bot.callback_query_handler(func=lambda call: is_owner(call.from_user.id) and call.data.startswith("admin_block:"))
def admin_block(call):
    user_id = int(call.data.split(":")[1])
    block_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} blocked.", show_alert=True)
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: is_owner(call.from_user.id) and call.data.startswith("admin_unblock:"))
def admin_unblock(call):
    user_id = int(call.data.split(":")[1])
    unblock_user(user_id)
    bot.answer_callback_query(call.id, f"User {user_id} unblocked.", show_alert=True)
    call.data = f"admin_user:{user_id}"
    admin_user_detail(call)

@bot.callback_query_handler(func=lambda call: is_owner(call.from_user.id) and call.data == "admin_back_users")
def admin_back_users(call):
    user_management(call.message)

@bot.message_handler(func=lambda m: is_owner(m.from_user.id) and m.text == "📊 Stats")
def stats(message):
    with get_db() as conn:
        total_keys = conn.execute("SELECT COUNT(*) FROM core_keys").fetchone()[0]
        active_keys = conn.execute("SELECT COUNT(*) FROM core_keys WHERE is_active=1").fetchone()[0]
        total_instances = conn.execute("SELECT COUNT(*) FROM instances").fetchone()[0]
        running_instances = conn.execute("SELECT COUNT(*) FROM instances WHERE status='running'").fetchone()[0]
        total_users = conn.execute("SELECT COUNT(DISTINCT user_id) FROM users").fetchone()[0]
    text = (
        f"📊 **System Statistics**\n\n"
        f"🗝 Keys: {total_keys} total, {active_keys} active\n"
        f"🖥 Instances: {total_instances} total, {running_instances} running\n"
        f"👥 Users: {total_users}\n"
    )
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.text == "🔙 Back" and is_owner(m.from_user.id))
def admin_back_to_main(message):
    user_id = message.from_user.id
    bot.send_message(message.chat.id, "Main menu:", reply_markup=main_menu(user_id))

@bot.message_handler(func=lambda m: True)
def fallback(message):
    user_id = message.from_user.id
    bot.send_message(message.chat.id, "Please use the menu buttons.", reply_markup=main_menu(user_id))

# ========================
#     ওয়েব ইঞ্জিন (Flask)
# ========================

WEB_ENGINE_ARGS = None  # কমান্ড লাইন আর্গুমেন্ট সংরক্ষণের জন্য

def create_web_app(port, password, directory, instance_uuid):
    """ইউজারের ওয়েব আইডিই Flask অ্যাপ তৈরি করে"""
    app = Flask(__name__, template_folder='templates')
    app.secret_key = os.urandom(24).hex()
    socketio_web = SocketIO(app, cors_allowed_origins="*")

    # ---------- লগইন পেজ (স্ট্রিং) ----------
    LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Web IDE Login</title>
    <style>
        body { background: #020617; color: white; font-family: 'Poppins', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-box { background: rgba(15,23,42,0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); width: 300px; }
        h2 { margin-bottom: 20px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border-radius: 10px; border: none; background: rgba(255,255,255,0.1); color: white; }
        button { background: linear-gradient(135deg, #8b5cf6, #3b82f6); border: none; padding: 12px; border-radius: 10px; color: white; width: 100%; cursor: pointer; }
        .error { color: #ef4444; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Web IDE Login</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="post">
            <input type="password" name="password" placeholder="Enter your password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""

    # ---------- অথেনটিকেশন ডেকোরেটর ----------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated_function

    # ---------- রাউটসমূহ ----------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            if request.form.get('password') == password:
                session['authenticated'] = True
                return redirect('/')
            else:
                return render_template_string(LOGIN_PAGE, error="Invalid password")
        return render_template_string(LOGIN_PAGE, error=None)

    @app.route('/logout')
    def logout():
        session.pop('authenticated', None)
        return redirect('/login')

    @app.route('/')
    @login_required
    def index():
        return render_template('index.html', username=instance_uuid[:8])

    @app.route('/files/<path:filename>')
    @login_required
    def serve_file(filename):
        return send_from_directory(directory, filename)

    # ---------- সকেটআইও ইভেন্ট (টার্মিনাল, ফাইল ম্যানেজার) ----------
    @socketio_web.on('connect')
    @login_required
    def handle_connect():
        emit('log', {'type': 'info', 'msg': 'Connected to Web IDE'})

    @socketio_web.on('get_files')
    @login_required
    def handle_get_files():
        files = []
        try:
            for f in os.listdir(directory):
                full = os.path.join(directory, f)
                if os.path.isfile(full):
                    files.append({
                        'name': f,
                        'hosted': False,
                        'port': None
                    })
        except:
            pass
        emit('file_list', {'files': files})

    @socketio_web.on('load_file')
    @login_required
    def handle_load_file(data):
        filename = data.get('filename')
        filepath = os.path.join(directory, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            emit('file_data', {'filename': filename, 'code': code})
            emit('log', {'type': 'info', 'msg': f'Loaded {filename}'})
        else:
            emit('log', {'type': 'error', 'msg': f'File not found: {filename}'})

    @socketio_web.on('save_run')
    @login_required
    def handle_save_run(data):
        filename = data.get('filename')
        code = data.get('code', '')
        if not filename:
            return
        filepath = os.path.join(directory, filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(code)
            emit('log', {'type': 'info', 'msg': f'Saved {filename}'})
        except Exception as e:
            emit('log', {'type': 'error', 'msg': f'Save failed: {e}'})
        handle_get_files()

    @socketio_web.on('delete_file')
    @login_required
    def handle_delete_file(data):
        filename = data.get('filename')
        filepath = os.path.join(directory, filename)
        try:
            os.remove(filepath)
            emit('log', {'type': 'info', 'msg': f'Deleted {filename}'})
        except Exception as e:
            emit('log', {'type': 'error', 'msg': f'Delete failed: {e}'})
        handle_get_files()

    @socketio_web.on('execute_command')
    @login_required
    def handle_execute_command(data):
        command = data.get('command')
        if not command:
            return
        emit('log', {'type': 'cmd', 'msg': command})
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=directory,
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

    return app, socketio_web

# ========================
#     কমান্ড লাইন এন্ট্রি
# ========================

def run_bot():
    """বট চালু করে"""
    init_db()
    threading.Thread(target=expiry_checker, daemon=True).start()
    logger.info("Starting Telegram bot...")
    bot.infinity_polling()

def run_web_engine(port, password, directory, instance_uuid):
    """ওয়েব ইঞ্জিন চালু করে"""
    os.makedirs(directory, exist_ok=True)
    app, socketio_web = create_web_app(port, password, directory, instance_uuid)
    logger.info(f"Starting Web IDE on port {port} for instance {instance_uuid[:8]}")
    socketio_web.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)

def main():
    """প্রধান এন্ট্রি পয়েন্ট"""
    parser = argparse.ArgumentParser(description="Cyber 20 UN - Bot & Web Engine")
    parser.add_argument("--web-engine", action="store_true", help="Run as web engine")
    parser.add_argument("--port", type=int, help="Port for web engine")
    parser.add_argument("--password", type=str, help="Password for web engine")
    parser.add_argument("--directory", type=str, help="Workspace directory")
    parser.add_argument("--instance-uuid", type=str, help="Instance UUID")
    args = parser.parse_args()

    if args.web_engine:
        if not all([args.port, args.password, args.directory, args.instance_uuid]):
            print("Missing arguments for web engine")
            sys.exit(1)
        run_web_engine(args.port, args.password, args.directory, args.instance_uuid)
    else:
        run_bot()

if __name__ == "__main__":
    main()
