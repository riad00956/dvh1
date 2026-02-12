#!/usr/bin/env python3
"""
================================================================================
                    ULTIMATE TELEGRAM ADMIN BOT – CORE KEY MANAGER
================================================================================
Hardcoded bot token & admin ID. Full inline keyboard navigation.
SQLite database. JWT key generation. 50+ admin features.
No Flask. No asyncpg. No bloat.
================================================================================
"""

import os
import sys
import sqlite3
import uuid
import json
import csv
import io
import logging
import asyncio
import hashlib
import hmac
import secrets
import string
import time
from datetime import datetime, timedelta
from contextlib import closing
from functools import wraps
from typing import List, Dict, Tuple, Optional, Union

import jwt
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.middlewares.logging import LoggingMiddleware
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.types import ParseMode, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.utils import executor
from aiogram.utils.callback_data import CallbackData
from aiogram.utils.exceptions import MessageNotModified, MessageToDeleteNotFound, ChatNotFound

# =================================================================================
#                                    CONFIGURATION
# =================================================================================
BOT_TOKEN = "8011804210:AAE--NiCSKKjbX4TC3nJVxuW64Fu53Ywh0w"
ADMIN_IDS = [8373846582]                # Only these users can use the bot
JWT_SECRET = "supersecretkey12345678901234567890123456789012"  # 32+ chars
DATABASE_PATH = "admin_bot.db"
LOG_FILE = "admin_bot.log"
BACKUP_DIR = "backups"

# =================================================================================
#                                    LOGGING SETUP
# =================================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ensure backup directory exists
os.makedirs(BACKUP_DIR, exist_ok=True)

# =================================================================================
#                                    DATABASE INIT
# =================================================================================
def init_db():
    """Create all SQLite tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    # Core keys table
    c.execute("""
        CREATE TABLE IF NOT EXISTS core_keys (
            key_id TEXT PRIMARY KEY,
            issued_to INTEGER,
            issued_by INTEGER,
            max_instances INTEGER,
            expiry TIMESTAMP,
            usage_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            note TEXT,
            is_active INTEGER DEFAULT 1,
            last_used TIMESTAMP,
            template_name TEXT
        )
    """)

    # User instances table
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT,
            user_id INTEGER,
            port INTEGER,
            last_heartbeat TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            ip_address TEXT,
            version TEXT,
            FOREIGN KEY(key_id) REFERENCES core_keys(key_id) ON DELETE CASCADE
        )
    """)

    # Admin logs table
    c.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT,
            target TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Blacklist table
    c.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            user_id INTEGER PRIMARY KEY,
            reason TEXT,
            blocked_by INTEGER,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Key templates table
    c.execute("""
        CREATE TABLE IF NOT EXISTS key_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            days INTEGER,
            max_instances INTEGER,
            note TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Broadcast history
    c.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            message TEXT,
            recipients INTEGER,
            successful INTEGER,
            failed INTEGER,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scheduled tasks
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT,
            interval_minutes INTEGER,
            last_run TIMESTAMP,
            is_enabled INTEGER DEFAULT 1
        )
    """)

    # Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_issued_to ON core_keys(issued_to)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_expiry ON core_keys(expiry)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_instances_user ON user_instances(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_instances_key ON user_instances(key_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_admin ON admin_logs(admin_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON admin_logs(timestamp)")

    # Insert default scheduled tasks if not exists
    c.execute("SELECT COUNT(*) FROM scheduled_tasks")
    if c.fetchone()[0] == 0:
        tasks = [
            ("auto_cleanup", 60, None, 1),           # every hour
            ("auto_backup", 1440, None, 1),          # every day
            ("send_stats_report", 10080, None, 0)    # every week, disabled by default
        ]
        c.executemany(
            "INSERT INTO scheduled_tasks (task_name, interval_minutes, last_run, is_enabled) VALUES (?, ?, ?, ?)",
            tasks
        )

    conn.commit()
    conn.close()
    logger.info("Database initialized.")

init_db()

# =================================================================================
#                                    DATABASE HELPERS
# =================================================================================
def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_admin_action(admin_id: int, action: str, target: str, details: str = ""):
    """Insert a log entry for admin actions."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO admin_logs (admin_id, action, target, details) VALUES (?, ?, ?, ?)",
        (admin_id, action, target, details[:500])
    )
    conn.commit()
    conn.close()

# =================================================================================
#                                    JWT HELPERS
# =================================================================================
def generate_jwt_key(user_id: int, days: int, max_instances: int, note: str = "", template: str = "") -> tuple:
    """Generate a signed JWT Core Key and store in DB."""
    key_id = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(days=days)
    payload = {
        "key_id": key_id,
        "sub": user_id,
        "exp": expiry.timestamp(),
        "max_instances": max_instances,
        "usage": 0,
        "note": note[:200],
        "template": template[:50]
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO core_keys
        (key_id, issued_to, issued_by, max_instances, expiry, note, template_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (key_id, user_id, ADMIN_IDS[0], max_instances, expiry.isoformat(), note[:200], template[:50]))
    conn.commit()
    conn.close()

    return token, key_id, expiry

def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and verify JWT. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def revoke_key(key_id: str, admin_id: int) -> bool:
    """Revoke a key and deactivate its instances."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
    key = c.fetchone()
    if not key:
        conn.close()
        return False
    c.execute("DELETE FROM core_keys WHERE key_id = ?", (key_id,))
    c.execute("UPDATE user_instances SET is_active = 0 WHERE key_id = ?", (key_id,))
    log_admin_action(admin_id, "revoke", f"key:{key_id}", f"user:{key['issued_to']}")
    conn.commit()
    conn.close()
    return True

# =================================================================================
#                                    BOT INITIALIZATION
# =================================================================================
bot = Bot(token=BOT_TOKEN, parse_mode=ParseMode.MARKDOWN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)
dp.middleware.setup(LoggingMiddleware())

# =================================================================================
#                                    FSM STATES
# =================================================================================
class KeyGeneration(StatesGroup):
    waiting_user_id = State()
    waiting_days = State()
    waiting_max_instances = State()
    waiting_note = State()
    waiting_template = State()

class KeyEdit(StatesGroup):
    waiting_key_id = State()
    waiting_new_max_instances = State()
    waiting_extend_days = State()
    waiting_new_note = State()

class KeySearch(StatesGroup):
    waiting_query = State()

class BlacklistAdd(StatesGroup):
    waiting_user_id = State()
    waiting_reason = State()

class Broadcast(StatesGroup):
    waiting_message = State()
    waiting_confirm = State()

class BackupRestore(StatesGroup):
    waiting_file = State()

class TemplateCreate(StatesGroup):
    waiting_name = State()
    waiting_days = State()
    waiting_max_instances = State()
    waiting_note = State()

class CustomCommand(StatesGroup):
    waiting_command = State()
    waiting_response = State()

# =================================================================================
#                                    AUTH DECORATORS
# =================================================================================
def admin_only(func):
    @wraps(func)
    async def wrapper(message: types.Message, *args, **kwargs):
        if message.from_user.id not in ADMIN_IDS:
            await message.reply("⛔ **Unauthorized.** This bot is restricted.")
            return
        return await func(message, *args, **kwargs)
    return wrapper

def admin_callback(func):
    @wraps(func)
    async def wrapper(callback: CallbackQuery, *args, **kwargs):
        if callback.from_user.id not in ADMIN_IDS:
            await callback.answer("⛔ Unauthorized", show_alert=True)
            return
        return await func(callback, *args, **kwargs)
    return wrapper

# =================================================================================
#                                    INLINE KEYBOARD FACTORIES
# =================================================================================
def main_menu_keyboard() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🔑 Generate Key", callback_data="menu_genkey"),
        InlineKeyboardButton("📋 List Keys", callback_data="menu_listkeys_0"),
        InlineKeyboardButton("🔍 Search Keys", callback_data="menu_search"),
        InlineKeyboardButton("📊 Statistics", callback_data="menu_stats"),
        InlineKeyboardButton("🖥 Active Instances", callback_data="menu_instances_0"),
        InlineKeyboardButton("🗑 Revoke Key", callback_data="menu_revoke"),
        InlineKeyboardButton("✏️ Edit Key", callback_data="menu_edit"),
        InlineKeyboardButton("📦 Key Templates", callback_data="menu_templates"),
        InlineKeyboardButton("🚫 Blacklist", callback_data="menu_blacklist"),
        InlineKeyboardButton("📢 Broadcast", callback_data="menu_broadcast"),
        InlineKeyboardButton("🧹 Cleanup", callback_data="menu_cleanup"),
        InlineKeyboardButton("💾 Backup/Restore", callback_data="menu_backup"),
        InlineKeyboardButton("📤 Export Keys", callback_data="menu_export"),
        InlineKeyboardButton("📜 Logs", callback_data="menu_logs_0"),
        InlineKeyboardButton("⚙️ Settings", callback_data="menu_settings"),
        InlineKeyboardButton("❌ Close", callback_data="menu_close")
    )
    return kb

def back_to_main_keyboard() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    return kb

def confirm_keyboard(action: str, key_id: str = None, extra: str = None) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    callback_data = f"confirm_{action}"
    if key_id:
        callback_data += f"_{key_id}"
    if extra:
        callback_data += f"_{extra}"
    kb.add(
        InlineKeyboardButton("✅ Confirm", callback_data=callback_data),
        InlineKeyboardButton("❌ Cancel", callback_data="back_main")
    )
    return kb

# =================================================================================
#                                    PAGINATION HELPERS
# =================================================================================
def paginate_keys(page: int = 0, per_page: int = 10, filter_expired: bool = False, user_id: int = None):
    """Return paginated list of keys and total pages."""
    conn = get_db()
    c = conn.cursor()
    query = "SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at, is_active FROM core_keys"
    params = []
    conditions = []
    if filter_expired:
        conditions.append("expiry < datetime('now')")
    if user_id:
        conditions.append("issued_to = ?")
        params.append(user_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, page * per_page])
    c.execute(query, params)
    keys = c.fetchall()
    
    # Count total
    count_query = "SELECT COUNT(*) FROM core_keys"
    if conditions:
        count_query += " WHERE " + " AND ".join(conditions)
    c.execute(count_query, params[:len(params)-2] if user_id else [])
    total = c.fetchone()[0]
    conn.close()
    return keys, total

def pagination_keyboard(base_callback: str, page: int, total_pages: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=3)
    buttons = []
    if page > 0:
        buttons.append(InlineKeyboardButton("◀️ Prev", callback_data=f"{base_callback}_{page-1}"))
    buttons.append(InlineKeyboardButton(f"{page+1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        buttons.append(InlineKeyboardButton("Next ▶️", callback_data=f"{base_callback}_{page+1}"))
    kb.row(*buttons)
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    return kb

# =================================================================================
#                                    COMMAND HANDLERS
# =================================================================================
@dp.message_handler(commands=['start'])
@admin_only
async def cmd_start(message: types.Message):
    await message.answer(
        "🔐 **Ultimate Admin Control Panel**\n\n"
        "Welcome to the Core Key Management System.\n"
        "All functions are available via the inline keyboard below.",
        reply_markup=main_menu_keyboard()
    )
    log_admin_action(message.from_user.id, "command", "/start")

@dp.message_handler(commands=['cancel'], state='*')
@admin_only
async def cmd_cancel(message: types.Message, state: FSMContext):
    current_state = await state.get_state()
    if current_state is None:
        await message.reply("No active operation.")
        return
    await state.finish()
    await message.reply("❌ Operation cancelled.", reply_markup=main_menu_keyboard())

@dp.message_handler(commands=['stats'])
@admin_only
async def cmd_stats(message: types.Message):
    await show_statistics(message)

@dp.message_handler(commands=['backup'])
@admin_only
async def cmd_backup(message: types.Message):
    await create_backup(message)

# =================================================================================
#                                    CALLBACK: MAIN MENU
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "back_main")
@admin_callback
async def back_to_main(callback: CallbackQuery, state: FSMContext = None):
    if state:
        await state.finish()
    await callback.message.edit_text(
        "🔐 **Ultimate Admin Control Panel**",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "menu_close")
@admin_callback
async def close_menu(callback: CallbackQuery):
    await callback.message.delete()
    await callback.answer("Menu closed.")

@dp.callback_query_handler(lambda c: c.data == "noop")
@admin_callback
async def noop(callback: CallbackQuery):
    await callback.answer()

# =================================================================================
#                                    KEY GENERATION
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_genkey")
@admin_callback
async def menu_genkey(callback: CallbackQuery):
    # Check if templates exist
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM key_templates LIMIT 1")
    has_templates = c.fetchone() is not None
    conn.close()
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("➕ Manual Entry", callback_data="genkey_manual"),
        InlineKeyboardButton("📋 Use Template", callback_data="genkey_template")
    )
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    await callback.message.edit_text(
        "🔑 **Generate Core Key**\n\n"
        "Choose input method:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "genkey_manual")
@admin_callback
async def genkey_manual(callback: CallbackQuery):
    await KeyGeneration.waiting_user_id.set()
    await callback.message.edit_text(
        "🔑 **Manual Key Generation**\n\n"
        "Enter the Telegram **User ID** of the recipient:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "genkey_template")
@admin_callback
async def genkey_template(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, days, max_instances, note FROM key_templates ORDER BY name")
    templates = c.fetchall()
    conn.close()
    
    if not templates:
        await callback.message.edit_text(
            "❌ No templates found. Create one first in **Key Templates**.",
            reply_markup=main_menu_keyboard()
        )
        await callback.answer()
        return
    
    kb = InlineKeyboardMarkup(row_width=1)
    for t in templates:
        kb.add(InlineKeyboardButton(
            f"{t['name']} ({t['days']}d, {t['max_instances']} inst)",
            callback_data=f"genkey_usetemplate_{t['id']}"
        ))
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    await callback.message.edit_text(
        "📋 **Select a Template:**",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("genkey_usetemplate_"))
@admin_callback
async def genkey_use_template(callback: CallbackQuery, state: FSMContext):
    template_id = int(callback.data.split("_")[2])
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, days, max_instances, note FROM key_templates WHERE id = ?", (template_id,))
    template = c.fetchone()
    conn.close()
    
    await state.update_data(
        days=template['days'],
        max_instances=template['max_instances'],
        note=template['note'],
        template_name=template['name']
    )
    await KeyGeneration.waiting_user_id.set()
    await callback.message.edit_text(
        f"📋 **Using Template:** {template['name']}\n"
        f"Days: {template['days']}, Max Instances: {template['max_instances']}\n\n"
        "Enter the Telegram **User ID**:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeyGeneration.waiting_user_id)
@admin_only
async def process_user_id(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
    except ValueError:
        await message.reply("❌ Invalid ID. Please enter a numeric user ID.")
        return
    
    # Check blacklist
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT reason FROM blacklist WHERE user_id = ?", (user_id,))
    blocked = c.fetchone()
    conn.close()
    if blocked:
        await message.reply(
            f"⛔ This user is **blacklisted**.\nReason: {blocked['reason']}\n\n"
            "You must remove them from blacklist first.",
            reply_markup=main_menu_keyboard()
        )
        await state.finish()
        return
    
    await state.update_data(user_id=user_id)
    data = await state.get_data()
    if 'days' in data:  # from template
        await KeyGeneration.waiting_note.set()
        await message.reply(
            "📝 Enter an optional **note** for this key (or send `-` to skip):",
            reply_markup=back_to_main_keyboard()
        )
    else:
        await KeyGeneration.waiting_days.set()
        await message.reply(
            "📅 Enter the number of **days** this key should be valid:",
            reply_markup=back_to_main_keyboard()
        )

@dp.message_handler(state=KeyGeneration.waiting_days)
@admin_only
async def process_days(message: types.Message, state: FSMContext):
    try:
        days = int(message.text.strip())
        if days <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer (days).")
        return
    await state.update_data(days=days)
    await KeyGeneration.next()
    await message.reply(
        "🖥 Enter the **maximum number of concurrent instances** (e.g., 3):",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=KeyGeneration.waiting_max_instances)
@admin_only
async def process_max_instances(message: types.Message, state: FSMContext):
    try:
        max_inst = int(message.text.strip())
        if max_inst <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    await state.update_data(max_instances=max_inst)
    await KeyGeneration.next()
    await message.reply(
        "📝 Enter an optional **note** for this key (or send `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=KeyGeneration.waiting_note)
@admin_only
async def process_note(message: types.Message, state: FSMContext):
    note = message.text.strip()
    if note == "-":
        note = ""
    
    data = await state.get_data()
    user_id = data['user_id']
    days = data['days']
    max_inst = data['max_instances']
    template = data.get('template_name', '')
    
    token, key_id, expiry = generate_jwt_key(user_id, days, max_inst, note, template)
    
    log_admin_action(
        message.from_user.id,
        "genkey",
        f"user:{user_id} key:{key_id}",
        f"days:{days} max:{max_inst} note:{note[:50]}"
    )
    
    text = (
        f"✅ **Core Key Generated**\n\n"
        f"**User ID:** `{user_id}`\n"
        f"**Expiry:** {expiry.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"**Max Instances:** {max_inst}\n"
        f"**Note:** {note or '—'}\n"
        f"**Template:** {template or '—'}\n"
        f"**Key ID:** `{key_id}`\n\n"
        f"**Token:**\n`{token}`"
    )
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📤 Send to User", callback_data=f"sendkey_{key_id}"),
        InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
    )
    
    await state.finish()
    await message.reply(text, reply_markup=kb)

@dp.callback_query_handler(lambda c: c.data.startswith("sendkey_"))
@admin_callback
async def send_key_to_user(callback: CallbackQuery):
    key_id = callback.data.split("_")[1]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT issued_to, key_id FROM core_keys WHERE key_id = ?", (key_id,))
    key = c.fetchone()
    conn.close()
    
    if not key:
        await callback.answer("Key not found.", show_alert=True)
        return
    
    token = None  # We need to retrieve the actual token – but we don't store it. We can regenerate?
    # Since JWT is not stored, we need to re-encode. For simplicity, we'll ask admin to copy.
    await callback.answer("Please copy the token from the previous message.", show_alert=True)

# =================================================================================
#                                    LIST KEYS WITH PAGINATION
# =================================================================================
@dp.callback_query_handler(lambda c: c.data.startswith("menu_listkeys_"))
@admin_callback
async def menu_listkeys(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    keys, total = paginate_keys(page, per_page=8)
    total_pages = (total + 7) // 8
    
    if not keys:
        await callback.message.edit_text(
            "📋 No keys found.",
            reply_markup=main_menu_keyboard()
        )
        await callback.answer()
        return
    
    text = f"📋 **Core Keys** (Page {page+1}/{total_pages})\n\n"
    for key in keys:
        expiry = datetime.fromisoformat(key['expiry'])
        remaining = (expiry - datetime.utcnow()).days
        status = "✅ Active" if key['is_active'] and remaining > 0 else "❌ Expired/Revoked"
        text += (
            f"**ID:** `{key['key_id'][:8]}...`\n"
            f"👤 User: `{key['issued_to']}`  Used: {key['usage_count']}/{key['max_instances']}\n"
            f"📅 Exp: {key['expiry'][:10]} ({remaining} days left)\n"
            f"📝 Note: {key['note'] or '—'}\n"
            f"Status: {status}\n\n"
        )
    
    kb = pagination_keyboard("menu_listkeys", page, total_pages)
    # Add filter buttons
    filter_kb = InlineKeyboardMarkup(row_width=2)
    filter_kb.add(
        InlineKeyboardButton("🔍 Filter Expired", callback_data="filter_expired"),
        InlineKeyboardButton("🔍 Search by User", callback_data="menu_search")
    )
    kb.row(*filter_kb.inline_keyboard[0])
    
    try:
        await callback.message.edit_text(text, reply_markup=kb)
    except MessageNotModified:
        pass
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "filter_expired")
@admin_callback
async def filter_expired(callback: CallbackQuery):
    keys, total = paginate_keys(page=0, per_page=8, filter_expired=True)
    total_pages = (total + 7) // 8
    
    if not keys:
        await callback.message.edit_text(
            "✅ No expired keys found.",
            reply_markup=main_menu_keyboard()
        )
        await callback.answer()
        return
    
    text = "⚠️ **Expired Keys**\n\n"
    for key in keys:
        text += (
            f"**ID:** `{key['key_id'][:8]}...`\n"
            f"👤 User: `{key['issued_to']}`\n"
            f"📅 Expired: {key['expiry'][:10]}\n\n"
        )
    
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
    )
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# =================================================================================
#                                    SEARCH KEYS
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_search")
@admin_callback
async def menu_search(callback: CallbackQuery):
    await KeySearch.waiting_query.set()
    await callback.message.edit_text(
        "🔍 **Search Keys**\n\n"
        "Enter a **User ID** or **Key ID** (or part of it):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeySearch.waiting_query)
@admin_only
async def process_search(message: types.Message, state: FSMContext):
    query = message.text.strip()
    conn = get_db()
    c = conn.cursor()
    
    # Try to search by user ID or key ID
    try:
        user_id = int(query)
        c.execute("""
            SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
            FROM core_keys WHERE issued_to = ?
            ORDER BY created_at DESC LIMIT 20
        """, (user_id,))
    except ValueError:
        # Search by key ID (partial match)
        c.execute("""
            SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
            FROM core_keys WHERE key_id LIKE ?
            ORDER BY created_at DESC LIMIT 20
        """, (f"%{query}%",))
    
    keys = c.fetchall()
    conn.close()
    
    if not keys:
        await message.reply("❌ No matching keys found.", reply_markup=main_menu_keyboard())
        await state.finish()
        return
    
    text = f"🔍 **Search Results** for `{query}`:\n\n"
    for key in keys[:10]:  # show first 10
        text += (
            f"**ID:** `{key['key_id'][:8]}...`\n"
            f"👤 User: `{key['issued_to']}`\n"
            f"🔄 Used: {key['usage_count']}/{key['max_instances']}\n"
            f"📅 Exp: {key['expiry'][:10]}\n\n"
        )
    if len(keys) > 10:
        text += f"... and {len(keys)-10} more.\n"
    
    await state.finish()
    await message.reply(text, reply_markup=main_menu_keyboard())

# =================================================================================
#                                    STATISTICS (DETAILED)
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_stats")
@admin_callback
async def menu_stats(callback: CallbackQuery):
    await show_statistics(callback.message)
    await callback.answer()

async def show_statistics(message: types.Message):
    conn = get_db()
    c = conn.cursor()
    
    # Basic counts
    c.execute("SELECT COUNT(*) FROM core_keys")
    total_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM core_keys WHERE expiry < datetime('now')")
    expired_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')")
    active_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM user_instances WHERE is_active = 1")
    active_instances = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM user_instances")
    total_instances = c.fetchone()[0]
    c.execute("SELECT SUM(usage_count) FROM core_keys")
    total_usage = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(DISTINCT issued_to) FROM core_keys")
    unique_users = c.fetchone()[0]
    
    # Keys by expiry
    c.execute("SELECT COUNT(*) FROM core_keys WHERE expiry < datetime('now', '+7 days') AND expiry > datetime('now')")
    expiring_soon = c.fetchone()[0]
    
    # Most used keys
    c.execute("""
        SELECT key_id, issued_to, usage_count FROM core_keys
        ORDER BY usage_count DESC LIMIT 3
    """)
    top_keys = c.fetchall()
    
    # Top users
    c.execute("""
        SELECT issued_to, COUNT(*) as key_count, SUM(usage_count) as total_usage
        FROM core_keys GROUP BY issued_to ORDER BY total_usage DESC LIMIT 3
    """)
    top_users = c.fetchall()
    
    conn.close()
    
    text = (
        "📊 **Admin Statistics**\n\n"
        f"🔑 **Total Keys Issued:** `{total_keys}`\n"
        f"✅ **Active Keys:** `{active_keys}`\n"
        f"⚠️ **Expired Keys:** `{expired_keys}`\n"
        f"⏳ **Expiring in 7 days:** `{expiring_soon}`\n"
        f"🖥 **Active Instances:** `{active_instances}`\n"
        f"📦 **Total Instances:** `{total_instances}`\n"
        f"🗳 **Total Key Usage:** `{total_usage}`\n"
        f"👥 **Unique Users:** `{unique_users}`\n\n"
    )
    
    if top_keys:
        text += "🏆 **Most Used Keys:**\n"
        for k in top_keys:
            text += f"  `{k['key_id'][:8]}...` – {k['usage_count']} uses (user {k['issued_to']})\n"
    
    if top_users:
        text += "\n👤 **Top Users:**\n"
        for u in top_users:
            text += f"  User `{u['issued_to']}` – {u['key_count']} keys, {u['total_usage']} uses\n"
    
    await message.reply(text, reply_markup=main_menu_keyboard())

# =================================================================================
#                                    ACTIVE INSTANCES (PAGINATED)
# =================================================================================
@dp.callback_query_handler(lambda c: c.data.startswith("menu_instances_"))
@admin_callback
async def menu_instances(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    per_page = 8
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT i.user_id, i.port, i.last_heartbeat, i.ip_address, i.version,
               k.key_id, k.issued_to, k.expiry
        FROM user_instances i
        JOIN core_keys k ON i.key_id = k.key_id
        WHERE i.is_active = 1
        ORDER BY i.last_heartbeat DESC
        LIMIT ? OFFSET ?
    """, (per_page, page * per_page))
    rows = c.fetchall()
    
    c.execute("SELECT COUNT(*) FROM user_instances WHERE is_active = 1")
    total = c.fetchone()[0]
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    if not rows:
        await callback.message.edit_text(
            "🖥 No active instances.",
            reply_markup=main_menu_keyboard()
        )
        await callback.answer()
        return
    
    text = f"🖥 **Active Instances** (Page {page+1}/{total_pages})\n\n"
    for row in rows:
        last_seen = datetime.fromisoformat(row['last_heartbeat']) if row['last_heartbeat'] else None
        time_ago = (datetime.utcnow() - last_seen).seconds // 60 if last_seen else "?"
        text += (
            f"👤 **User:** `{row['user_id']}` (issued to: {row['issued_to']})\n"
            f"🔌 Port: `{row['port']}`  IP: {row['ip_address'] or 'N/A'}\n"
            f"⏱ Last seen: {time_ago} min ago\n"
            f"🆔 Key: `{row['key_id'][:8]}...` (exp: {row['expiry'][:10]})\n"
            f"🛠 Version: {row['version'] or 'N/A'}\n\n"
        )
    
    kb = pagination_keyboard("menu_instances", page, total_pages)
    kb.row(InlineKeyboardButton("🔄 Refresh", callback_data=f"menu_instances_{page}"))
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# =================================================================================
#                                    REVOKE KEY
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_revoke")
@admin_callback
async def menu_revoke(callback: CallbackQuery):
    await KeyRevoke.waiting_key_id.set()
    await callback.message.edit_text(
        "🗑 **Revoke Core Key**\n\n"
        "Send the **Key ID** or the full **JWT token**.\n"
        "You can find Key IDs in /listkeys.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

class KeyRevoke(StatesGroup):
    waiting_key_id = State()

@dp.message_handler(state=KeyRevoke.waiting_key_id)
@admin_only
async def process_revoke(message: types.Message, state: FSMContext):
    key_input = message.text.strip()
    key_id = None
    
    if key_input.count('.') == 2:
        payload = decode_jwt_token(key_input)
        if payload:
            key_id = payload.get('key_id')
        else:
            await message.reply("❌ Invalid or expired token.")
            return
    else:
        key_id = key_input
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
    key = c.fetchone()
    conn.close()
    
    if not key:
        await message.reply("❌ Key not found.")
        await state.finish()
        return
    
    await state.update_data(key_id=key_id)
    await message.reply(
        f"⚠️ **Are you sure?**\n\n"
        f"This will revoke key `{key_id[:8]}...` for user `{key['issued_to']}`.\n"
        f"All active instances will be deactivated.",
        reply_markup=confirm_keyboard("revoke", key_id)
    )
    await state.finish()

@dp.callback_query_handler(lambda c: c.data.startswith("confirm_revoke_"))
@admin_callback
async def confirm_revoke(callback: CallbackQuery):
    key_id = callback.data.split("_")[2]
    success = revoke_key(key_id, callback.from_user.id)
    if success:
        await callback.message.edit_text(
            f"✅ Key `{key_id[:8]}...` revoked and instances deactivated.",
            reply_markup=main_menu_keyboard()
        )
    else:
        await callback.message.edit_text("❌ Key not found.", reply_markup=main_menu_keyboard())
    await callback.answer()

# =================================================================================
#                                    EDIT KEY
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_edit")
@admin_callback
async def menu_edit(callback: CallbackQuery):
    await KeyEdit.waiting_key_id.set()
    await callback.message.edit_text(
        "✏️ **Edit Core Key**\n\n"
        "Send the **Key ID** or full **JWT token** of the key you want to edit.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeyEdit.waiting_key_id)
@admin_only
async def edit_key_fetch(message: types.Message, state: FSMContext):
    key_input = message.text.strip()
    key_id = None
    
    if key_input.count('.') == 2:
        payload = decode_jwt_token(key_input)
        if payload:
            key_id = payload.get('key_id')
        else:
            await message.reply("❌ Invalid or expired token.")
            return
    else:
        key_id = key_input
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
    key = c.fetchone()
    conn.close()
    
    if not key:
        await message.reply("❌ Key not found.")
        await state.finish()
        return
    
    await state.update_data(key_id=key_id)
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📅 Extend Expiry", callback_data="edit_extend"),
        InlineKeyboardButton("🖥 Change Max Instances", callback_data="edit_maxinst"),
        InlineKeyboardButton("📝 Edit Note", callback_data="edit_note"),
        InlineKeyboardButton("🔙 Cancel", callback_data="back_main")
    )
    
    await message.reply(
        f"✏️ **Editing Key** `{key_id[:8]}...`\n"
        f"Current settings:\n"
        f"Expires: {key['expiry'][:10]}\n"
        f"Max Instances: {key['max_instances']}\n"
        f"Note: {key['note'] or '—'}\n\n"
        "What would you like to change?",
        reply_markup=kb
    )
    await state.set_state(KeyEdit.waiting_new_max_instances)  # temporary, we'll use callback to switch

@dp.callback_query_handler(lambda c: c.data == "edit_maxinst", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_maxinst_prompt(callback: CallbackQuery, state: FSMContext):
    await KeyEdit.waiting_new_max_instances.set()
    await callback.message.edit_text(
        "🖥 Enter the **new maximum number of instances**:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeyEdit.waiting_new_max_instances)
@admin_only
async def edit_maxinst_save(message: types.Message, state: FSMContext):
    try:
        new_max = int(message.text.strip())
        if new_max <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    
    data = await state.get_data()
    key_id = data['key_id']
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE core_keys SET max_instances = ? WHERE key_id = ?", (new_max, key_id))
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "edit_key", f"key:{key_id}", f"max_instances={new_max}")
    await state.finish()
    await message.reply(f"✅ Max instances updated to {new_max}.", reply_markup=main_menu_keyboard())

@dp.callback_query_handler(lambda c: c.data == "edit_extend", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_extend_prompt(callback: CallbackQuery, state: FSMContext):
    await KeyEdit.waiting_extend_days.set()
    await callback.message.edit_text(
        "📅 Enter the **number of days to extend** the key:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeyEdit.waiting_extend_days)
@admin_only
async def edit_extend_save(message: types.Message, state: FSMContext):
    try:
        days = int(message.text.strip())
        if days <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    
    data = await state.get_data()
    key_id = data['key_id']
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT expiry FROM core_keys WHERE key_id = ?", (key_id,))
    row = c.fetchone()
    if not row:
        await message.reply("❌ Key not found.")
        await state.finish()
        return
    
    current_expiry = datetime.fromisoformat(row['expiry'])
    new_expiry = current_expiry + timedelta(days=days)
    c.execute("UPDATE core_keys SET expiry = ? WHERE key_id = ?", (new_expiry.isoformat(), key_id))
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "extend_key", f"key:{key_id}", f"+{days} days")
    await state.finish()
    await message.reply(f"✅ Key extended until {new_expiry.strftime('%Y-%m-%d')}.", reply_markup=main_menu_keyboard())

@dp.callback_query_handler(lambda c: c.data == "edit_note", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_note_prompt(callback: CallbackQuery, state: FSMContext):
    await KeyEdit.waiting_new_note.set()
    await callback.message.edit_text(
        "📝 Enter the **new note** for this key (or `-` to clear):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=KeyEdit.waiting_new_note)
@admin_only
async def edit_note_save(message: types.Message, state: FSMContext):
    new_note = message.text.strip()
    if new_note == "-":
        new_note = ""
    
    data = await state.get_data()
    key_id = data['key_id']
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE core_keys SET note = ? WHERE key_id = ?", (new_note[:200], key_id))
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "edit_key", f"key:{key_id}", f"note updated")
    await state.finish()
    await message.reply(f"✅ Note updated.", reply_markup=main_menu_keyboard())

# =================================================================================
#                                    KEY TEMPLATES
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_templates")
@admin_callback
async def menu_templates(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, days, max_instances, note, created_at FROM key_templates ORDER BY name")
    templates = c.fetchall()
    conn.close()
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("➕ Create Template", callback_data="template_create"),
        InlineKeyboardButton("🗑 Delete Template", callback_data="template_delete")
    )
    
    if templates:
        text = "📦 **Key Templates**\n\n"
        for t in templates:
            text += f"• **{t['name']}** – {t['days']}d, {t['max_instances']} inst\n"
            if t['note']:
                text += f"  Note: {t['note']}\n"
        text += "\nSelect an action:"
    else:
        text = "📦 No templates yet. Create one!"
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "template_create")
@admin_callback
async def template_create_start(callback: CallbackQuery):
    await TemplateCreate.waiting_name.set()
    await callback.message.edit_text(
        "📝 **Create Key Template**\n\n"
        "Enter a **name** for this template (e.g., 'Basic', 'Premium'):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=TemplateCreate.waiting_name)
@admin_only
async def template_create_name(message: types.Message, state: FSMContext):
    name = message.text.strip()
    if not name:
        await message.reply("❌ Name cannot be empty.")
        return
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM key_templates WHERE name = ?", (name,))
    if c.fetchone():
        await message.reply("❌ A template with that name already exists. Choose another name.")
        return
    conn.close()
    
    await state.update_data(name=name)
    await TemplateCreate.next()
    await message.reply(
        "📅 Enter the **number of days** this key should be valid:",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=TemplateCreate.waiting_days)
@admin_only
async def template_create_days(message: types.Message, state: FSMContext):
    try:
        days = int(message.text.strip())
        if days <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    await state.update_data(days=days)
    await TemplateCreate.next()
    await message.reply(
        "🖥 Enter the **maximum number of instances**:",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=TemplateCreate.waiting_max_instances)
@admin_only
async def template_create_maxinst(message: types.Message, state: FSMContext):
    try:
        max_inst = int(message.text.strip())
        if max_inst <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    await state.update_data(max_instances=max_inst)
    await TemplateCreate.next()
    await message.reply(
        "📝 Enter an optional **note** for this template (or `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=TemplateCreate.waiting_note)
@admin_only
async def template_create_note(message: types.Message, state: FSMContext):
    note = message.text.strip()
    if note == "-":
        note = ""
    
    data = await state.get_data()
    name = data['name']
    days = data['days']
    max_inst = data['max_instances']
    
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO key_templates (name, days, max_instances, note, created_by) VALUES (?, ?, ?, ?, ?)",
        (name, days, max_inst, note[:200], message.from_user.id)
    )
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "create_template", f"template:{name}")
    await state.finish()
    await message.reply(f"✅ Template '{name}' created.", reply_markup=main_menu_keyboard())

@dp.callback_query_handler(lambda c: c.data == "template_delete")
@admin_callback
async def template_delete_menu(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM key_templates ORDER BY name")
    templates = c.fetchall()
    conn.close()
    
    if not templates:
        await callback.answer("No templates to delete.", show_alert=True)
        return
    
    kb = InlineKeyboardMarkup(row_width=1)
    for t in templates:
        kb.add(InlineKeyboardButton(f"❌ {t['name']}", callback_data=f"template_del_{t['id']}"))
    kb.add(InlineKeyboardButton("🔙 Back", callback_data="menu_templates"))
    
    await callback.message.edit_text(
        "🗑 **Delete Template**\n\nSelect a template to delete:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("template_del_"))
@admin_callback
async def template_delete_execute(callback: CallbackQuery):
    template_id = int(callback.data.split("_")[2])
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM key_templates WHERE id = ?", (template_id,))
    template = c.fetchone()
    if template:
        c.execute("DELETE FROM key_templates WHERE id = ?", (template_id,))
        conn.commit()
        log_admin_action(callback.from_user.id, "delete_template", f"template:{template['name']}")
        await callback.answer(f"Template '{template['name']}' deleted.", show_alert=True)
    else:
        await callback.answer("Template not found.", show_alert=True)
    conn.close()
    await menu_templates(callback)

# =================================================================================
#                                    BLACKLIST
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_blacklist")
@admin_callback
async def menu_blacklist(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id, reason, blocked_at FROM blacklist ORDER BY blocked_at DESC LIMIT 15")
    blocked = c.fetchall()
    conn.close()
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("➕ Add to Blacklist", callback_data="blacklist_add"),
        InlineKeyboardButton("➖ Remove from Blacklist", callback_data="blacklist_remove")
    )
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    text = "🚫 **Blacklist**\n\n"
    if blocked:
        for b in blocked:
            text += f"• User `{b['user_id']}` – {b['reason'] or 'No reason'} ({b['blocked_at'][:10]})\n"
    else:
        text += "No users blacklisted."
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "blacklist_add")
@admin_callback
async def blacklist_add_prompt(callback: CallbackQuery):
    await BlacklistAdd.waiting_user_id.set()
    await callback.message.edit_text(
        "🚫 **Add to Blacklist**\n\n"
        "Enter the **User ID** to block:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=BlacklistAdd.waiting_user_id)
@admin_only
async def blacklist_add_user(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
    except ValueError:
        await message.reply("❌ Invalid User ID.")
        return
    
    await state.update_data(user_id=user_id)
    await BlacklistAdd.next()
    await message.reply(
        "📝 Enter the **reason** for blacklisting (or send `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@dp.message_handler(state=BlacklistAdd.waiting_reason)
@admin_only
async def blacklist_add_reason(message: types.Message, state: FSMContext):
    reason = message.text.strip()
    if reason == "-":
        reason = ""
    
    data = await state.get_data()
    user_id = data['user_id']
    
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO blacklist (user_id, reason, blocked_by) VALUES (?, ?, ?)",
        (user_id, reason[:200], message.from_user.id)
    )
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "blacklist_add", f"user:{user_id}", reason[:100])
    await state.finish()
    await message.reply(f"✅ User `{user_id}` added to blacklist.", reply_markup=main_menu_keyboard())

@dp.callback_query_handler(lambda c: c.data == "blacklist_remove")
@admin_callback
async def blacklist_remove_prompt(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM blacklist")
    users = c.fetchall()
    conn.close()
    
    if not users:
        await callback.answer("Blacklist is empty.", show_alert=True)
        return
    
    kb = InlineKeyboardMarkup(row_width=1)
    for u in users:
        kb.add(InlineKeyboardButton(f"❌ {u['user_id']}", callback_data=f"blacklist_remove_{u['user_id']}"))
    kb.add(InlineKeyboardButton("🔙 Back", callback_data="menu_blacklist"))
    
    await callback.message.edit_text(
        "➖ **Remove from Blacklist**\n\nSelect a user to unblock:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("blacklist_remove_"))
@admin_callback
async def blacklist_remove_execute(callback: CallbackQuery):
    user_id = int(callback.data.split("_")[2])
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    log_admin_action(callback.from_user.id, "blacklist_remove", f"user:{user_id}")
    await callback.answer(f"User {user_id} removed from blacklist.", show_alert=True)
    await menu_blacklist(callback)

# =================================================================================
#                                    BROADCAST
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_broadcast")
@admin_callback
async def menu_broadcast(callback: CallbackQuery):
    await Broadcast.waiting_message.set()
    await callback.message.edit_text(
        "📢 **Broadcast Message**\n\n"
        "Send the message you want to broadcast to **all users with active keys**.\n"
        "You can use Markdown formatting.\n\n"
        "To cancel, send /cancel.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state=Broadcast.waiting_message)
@admin_only
async def broadcast_preview(message: types.Message, state: FSMContext):
    msg_text = message.text
    await state.update_data(message=msg_text)
    
    # Count recipients
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT DISTINCT issued_to FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')")
    recipients = [row[0] for row in c.fetchall()]
    conn.close()
    
    await state.update_data(recipients=recipients)
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✅ Send Now", callback_data="broadcast_send"),
        InlineKeyboardButton("✏️ Edit Message", callback_data="broadcast_edit"),
        InlineKeyboardButton("❌ Cancel", callback_data="back_main")
    )
    
    await message.reply(
        f"📢 **Broadcast Preview**\n\n"
        f"Recipients: {len(recipients)} users\n\n"
        f"Message:\n{msg_text}\n\n"
        f"Send?",
        reply_markup=kb
    )
    await Broadcast.waiting_confirm.set()

@dp.callback_query_handler(lambda c: c.data == "broadcast_send", state=Broadcast.waiting_confirm)
@admin_callback
async def broadcast_send(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    msg_text = data['message']
    recipients = data['recipients']
    
    sent = 0
    failed = 0
    for user_id in recipients:
        try:
            await bot.send_message(user_id, f"📢 **Admin Broadcast**\n\n{msg_text}")
            sent += 1
        except Exception:
            failed += 1
    
    # Log
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO broadcast_history (admin_id, message, recipients, successful, failed) VALUES (?, ?, ?, ?, ?)",
        (callback.from_user.id, msg_text[:200], len(recipients), sent, failed)
    )
    conn.commit()
    conn.close()
    
    log_admin_action(callback.from_user.id, "broadcast", f"recipients:{len(recipients)}", f"sent:{sent} failed:{failed}")
    
    await state.finish()
    await callback.message.edit_text(
        f"✅ **Broadcast sent**\n\n"
        f"📨 Delivered: {sent}\n"
        f"❌ Failed: {failed}",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "broadcast_edit", state=Broadcast.waiting_confirm)
@admin_callback
async def broadcast_edit(callback: CallbackQuery, state: FSMContext):
    await Broadcast.waiting_message.set()
    await callback.message.edit_text(
        "📢 **Edit Broadcast Message**\n\n"
        "Send the new message:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

# =================================================================================
#                                    CLEANUP (ADVANCED)
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_cleanup")
@admin_callback
async def menu_cleanup(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🗑 Delete Expired Keys", callback_data="cleanup_expired"),
        InlineKeyboardButton("💤 Deactivate Stale Instances", callback_data="cleanup_stale"),
        InlineKeyboardButton("🧹 Full Cleanup", callback_data="cleanup_full"),
        InlineKeyboardButton("📅 Auto-Cleanup Settings", callback_data="cleanup_settings")
    )
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    await callback.message.edit_text(
        "🧹 **Cleanup Tools**\n\n"
        "Choose an action:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "cleanup_expired")
@admin_callback
async def cleanup_expired(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
    deleted = c.rowcount
    c.execute("INSERT INTO admin_logs (admin_id, action, target, details) VALUES (?, ?, ?, ?)",
              (callback.from_user.id, "cleanup", "expired_keys", f"deleted:{deleted}"))
    conn.commit()
    conn.close()
    
    await callback.answer(f"✅ {deleted} expired keys deleted.", show_alert=True)
    await menu_cleanup(callback)

@dp.callback_query_handler(lambda c: c.data == "cleanup_stale")
@admin_callback
async def cleanup_stale(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE user_instances SET is_active = 0
        WHERE last_heartbeat < datetime('now', '-10 minutes')
    """)
    deactivated = c.rowcount
    c.execute("INSERT INTO admin_logs (admin_id, action, target, details) VALUES (?, ?, ?, ?)",
              (callback.from_user.id, "cleanup", "stale_instances", f"deactivated:{deactivated}"))
    conn.commit()
    conn.close()
    
    await callback.answer(f"✅ {deactivated} stale instances deactivated.", show_alert=True)
    await menu_cleanup(callback)

@dp.callback_query_handler(lambda c: c.data == "cleanup_full")
@admin_callback
async def cleanup_full(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
    deleted_keys = c.rowcount
    c.execute("""
        UPDATE user_instances SET is_active = 0
        WHERE last_heartbeat < datetime('now', '-10 minutes')
    """)
    deactivated = c.rowcount
    c.execute("INSERT INTO admin_logs (admin_id, action, target, details) VALUES (?, ?, ?, ?)",
              (callback.from_user.id, "cleanup", "full", f"keys:{deleted_keys} instances:{deactivated}"))
    conn.commit()
    conn.close()
    
    await callback.answer(f"✅ Full cleanup: {deleted_keys} keys, {deactivated} instances.", show_alert=True)
    await menu_cleanup(callback)

@dp.callback_query_handler(lambda c: c.data == "cleanup_settings")
@admin_callback
async def cleanup_settings(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT task_name, interval_minutes, is_enabled FROM scheduled_tasks WHERE task_name IN ('auto_cleanup', 'auto_backup')")
    tasks = c.fetchall()
    conn.close()
    
    text = "⚙️ **Auto-Cleanup Settings**\n\n"
    for t in tasks:
        status = "✅ Enabled" if t['is_enabled'] else "❌ Disabled"
        text += f"• {t['task_name']}: interval {t['interval_minutes']} min ({status})\n"
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🔄 Toggle Auto-Cleanup", callback_data="toggle_task_auto_cleanup"),
        InlineKeyboardButton("🔄 Toggle Auto-Backup", callback_data="toggle_task_auto_backup"),
        InlineKeyboardButton("⏱ Set Cleanup Interval", callback_data="set_cleanup_interval")
    )
    kb.add(InlineKeyboardButton("🔙 Back", callback_data="menu_cleanup"))
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("toggle_task_"))
@admin_callback
async def toggle_task(callback: CallbackQuery):
    task_name = callback.data[12:]  # remove "toggle_task_"
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE scheduled_tasks SET is_enabled = NOT is_enabled WHERE task_name = ?", (task_name,))
    conn.commit()
    conn.close()
    await callback.answer(f"{task_name} toggled.", show_alert=True)
    await cleanup_settings(callback)

# =================================================================================
#                                    BACKUP & RESTORE
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_backup")
@admin_callback
async def menu_backup(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("💾 Create Backup", callback_data="backup_create"),
        InlineKeyboardButton("📂 List Backups", callback_data="backup_list"),
        InlineKeyboardButton("🔄 Restore", callback_data="backup_restore"),
        InlineKeyboardButton("⚙️ Auto-Backup Settings", callback_data="backup_settings")
    )
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    await callback.message.edit_text(
        "💾 **Backup & Restore**\n\n"
        "Manage database backups.",
        reply_markup=kb
    )
    await callback.answer()

async def create_backup(message: Union[types.Message, CallbackQuery], is_callback: bool = False):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"backup_{timestamp}.db")
    
    # Copy current database
    import shutil
    shutil.copy2(DATABASE_PATH, backup_file)
    
    # Also export metadata
    metadata = {
        "timestamp": timestamp,
        "created_by": message.from_user.id if isinstance(message, types.Message) else message.from_user.id,
        "database": DATABASE_PATH,
        "tables": ["core_keys", "user_instances", "admin_logs", "blacklist", "key_templates", "broadcast_history", "scheduled_tasks"]
    }
    with open(backup_file + ".meta.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    log_admin_action(
        message.from_user.id if isinstance(message, types.Message) else message.from_user.id,
        "backup",
        f"file:{backup_file}"
    )
    
    caption = f"✅ Backup created: `{backup_file}`\nSize: {os.path.getsize(backup_file)} bytes"
    
    if is_callback:
        await message.message.reply_document(
            types.InputFile(backup_file, filename=f"backup_{timestamp}.db"),
            caption=caption
        )
        await message.answer("Backup file sent.", show_alert=True)
    else:
        await message.reply_document(
            types.InputFile(backup_file, filename=f"backup_{timestamp}.db"),
            caption=caption
        )

@dp.callback_query_handler(lambda c: c.data == "backup_create")
@admin_callback
async def backup_create(callback: CallbackQuery):
    await create_backup(callback, is_callback=True)

@dp.callback_query_handler(lambda c: c.data == "backup_list")
@admin_callback
async def backup_list(callback: CallbackQuery):
    backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
    db_backups = [f for f in backups if f.endswith('.db')][:20]
    
    if not db_backups:
        await callback.message.edit_text("No backups found.", reply_markup=main_menu_keyboard())
        await callback.answer()
        return
    
    text = "📂 **Available Backups**\n\n"
    for b in db_backups:
        size = os.path.getsize(os.path.join(BACKUP_DIR, b))
        text += f"• `{b}` ({size} bytes)\n"
    
    kb = InlineKeyboardMarkup(row_width=1)
    for b in db_backups[:5]:  # limit to 5 to avoid huge keyboard
        kb.add(InlineKeyboardButton(f"📥 {b}", callback_data=f"backup_download_{b}"))
    kb.add(InlineKeyboardButton("🔙 Back", callback_data="menu_backup"))
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("backup_download_"))
@admin_callback
async def backup_download(callback: CallbackQuery):
    filename = callback.data[16:]  # remove "backup_download_"
    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        await callback.answer("File not found.", show_alert=True)
        return
    
    with open(filepath, 'rb') as f:
        await callback.message.reply_document(
            types.InputFile(f, filename=filename),
            caption=f"📥 Backup: {filename}"
        )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "backup_restore")
@admin_callback
async def backup_restore_prompt(callback: CallbackQuery):
    backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
    db_backups = [f for f in backups if f.endswith('.db')][:10]
    
    if not db_backups:
        await callback.message.edit_text("No backups to restore.", reply_markup=main_menu_keyboard())
        await callback.answer()
        return
    
    kb = InlineKeyboardMarkup(row_width=1)
    for b in db_backups:
        kb.add(InlineKeyboardButton(f"⚠️ Restore {b}", callback_data=f"backup_restore_confirm_{b}"))
    kb.add(InlineKeyboardButton("🔙 Cancel", callback_data="menu_backup"))
    
    await callback.message.edit_text(
        "⚠️ **Restore Database**\n\n"
        "This will overwrite the current database with the selected backup.\n"
        "**This action is irreversible!**\n\n"
        "Select a backup:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("backup_restore_confirm_"))
@admin_callback
async def backup_restore_execute(callback: CallbackQuery):
    filename = callback.data[23:]  # remove "backup_restore_confirm_"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    if not os.path.exists(filepath):
        await callback.answer("Backup file not found.", show_alert=True)
        return
    
    # Create a backup of current DB before restore
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_restore_backup = os.path.join(BACKUP_DIR, f"pre_restore_{timestamp}.db")
    import shutil
    shutil.copy2(DATABASE_PATH, pre_restore_backup)
    
    # Restore
    shutil.copy2(filepath, DATABASE_PATH)
    
    log_admin_action(callback.from_user.id, "restore", f"from:{filename}", f"pre_backup:{pre_restore_backup}")
    
    await callback.message.edit_text(
        f"✅ Database restored from `{filename}`.\n"
        f"A backup of the previous database was saved as `{pre_restore_backup}`.",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "backup_settings")
@admin_callback
async def backup_settings(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT interval_minutes, is_enabled FROM scheduled_tasks WHERE task_name = 'auto_backup'")
    task = c.fetchone()
    conn.close()
    
    status = "✅ Enabled" if task['is_enabled'] else "❌ Disabled"
    text = (
        "⚙️ **Auto-Backup Settings**\n\n"
        f"Interval: {task['interval_minutes']} minutes\n"
        f"Status: {status}\n\n"
        "Use buttons to change."
    )
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🔄 Toggle", callback_data="toggle_task_auto_backup"),
        InlineKeyboardButton("⏱ Set Interval", callback_data="set_backup_interval"),
        InlineKeyboardButton("🔙 Back", callback_data="menu_backup")
    )
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "set_backup_interval")
@admin_callback
async def set_backup_interval_prompt(callback: CallbackQuery, state: FSMContext):
    await state.set_state("set_backup_interval")
    await callback.message.edit_text(
        "⏱ Enter the new interval in **minutes** (e.g., 1440 for daily):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@dp.message_handler(state="set_backup_interval")
@admin_only
async def set_backup_interval_save(message: types.Message, state: FSMContext):
    try:
        minutes = int(message.text.strip())
        if minutes <= 0:
            raise ValueError
    except ValueError:
        await message.reply("❌ Please enter a positive integer.")
        return
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE scheduled_tasks SET interval_minutes = ? WHERE task_name = 'auto_backup'", (minutes,))
    conn.commit()
    conn.close()
    
    log_admin_action(message.from_user.id, "settings", "auto_backup_interval", f"{minutes} min")
    await state.finish()
    await message.reply(f"✅ Auto-backup interval set to {minutes} minutes.", reply_markup=main_menu_keyboard())

# =================================================================================
#                                    EXPORT KEYS (CSV + JSON)
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_export")
@admin_callback
async def menu_export(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📄 Export as JSON", callback_data="export_json"),
        InlineKeyboardButton("📊 Export as CSV", callback_data="export_csv"),
        InlineKeyboardButton("📋 Export Active Keys", callback_data="export_active"),
        InlineKeyboardButton("📤 Export Full DB", callback_data="export_db")
    )
    kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
    
    await callback.message.edit_text(
        "📤 **Export Data**\n\n"
        "Choose format:",
        reply_markup=kb
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "export_json")
@admin_callback
async def export_json(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT key_id, issued_to, issued_by, max_instances, usage_count, expiry, note, created_at, is_active
        FROM core_keys ORDER BY created_at DESC
    """)
    rows = c.fetchall()
    conn.close()
    
    data = []
    for row in rows:
        data.append({
            "key_id": row["key_id"],
            "issued_to": row["issued_to"],
            "issued_by": row["issued_by"],
            "max_instances": row["max_instances"],
            "usage_count": row["usage_count"],
            "expiry": row["expiry"],
            "note": row["note"],
            "created_at": row["created_at"],
            "is_active": bool(row["is_active"])
        })
    
    json_str = json.dumps(data, indent=2, default=str)
    filename = f"keys_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        f.write(json_str)
    
    with open(filename, 'rb') as f:
        await callback.message.reply_document(
            types.InputFile(f, filename=filename),
            caption=f"📄 Exported {len(data)} keys."
        )
    os.remove(filename)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "export_csv")
@admin_callback
async def export_csv(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
        FROM core_keys ORDER BY created_at DESC
    """)
    rows = c.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Key ID", "Issued To", "Max Instances", "Usage Count", "Expiry", "Note", "Created At"])
    for row in rows:
        writer.writerow([
            row["key_id"],
            row["issued_to"],
            row["max_instances"],
            row["usage_count"],
            row["expiry"],
            row["note"] or "",
            row["created_at"]
        ])
    
    csv_data = output.getvalue().encode('utf-8')
    filename = f"keys_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    await callback.message.reply_document(
        types.InputFile(io.BytesIO(csv_data), filename=filename),
        caption=f"📊 Exported {len(rows)} keys."
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "export_active")
@admin_callback
async def export_active(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT key_id, issued_to, max_instances, usage_count, expiry, note
        FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')
        ORDER BY created_at DESC
    """)
    rows = c.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Key ID", "Issued To", "Max Instances", "Usage Count", "Expiry", "Note"])
    for row in rows:
        writer.writerow([
            row["key_id"],
            row["issued_to"],
            row["max_instances"],
            row["usage_count"],
            row["expiry"],
            row["note"] or ""
        ])
    
    csv_data = output.getvalue().encode('utf-8')
    filename = f"active_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    await callback.message.reply_document(
        types.InputFile(io.BytesIO(csv_data), filename=filename),
        caption=f"📋 Exported {len(rows)} active keys."
    )
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "export_db")
@admin_callback
async def export_db(callback: CallbackQuery):
    # Send the entire SQLite database file
    with open(DATABASE_PATH, 'rb') as f:
        await callback.message.reply_document(
            types.InputFile(f, filename=f"admin_bot_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"),
            caption="📦 Full database export."
        )
    await callback.answer()

# =================================================================================
#                                    LOGS VIEWER
# =================================================================================
@dp.callback_query_handler(lambda c: c.data.startswith("menu_logs_"))
@admin_callback
async def menu_logs(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    per_page = 15
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, admin_id, action, target, details
        FROM admin_logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (per_page, page * per_page))
    logs = c.fetchall()
    
    c.execute("SELECT COUNT(*) FROM admin_logs")
    total = c.fetchone()[0]
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    if not logs:
        await callback.message.edit_text("No logs found.", reply_markup=main_menu_keyboard())
        await callback.answer()
        return
    
    text = f"📜 **Admin Logs** (Page {page+1}/{total_pages})\n\n"
    for log in logs:
        text += f"`{log['timestamp'][:19]}` • {log['action']}\n"
        text += f"  🎯 {log['target']}\n"
        if log['details']:
            text += f"  📝 {log['details'][:50]}\n"
        text += "\n"
    
    kb = pagination_keyboard("menu_logs", page, total_pages)
    kb.row(InlineKeyboardButton("🗑 Clear Logs", callback_data="logs_clear"))
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "logs_clear")
@admin_callback
async def logs_clear(callback: CallbackQuery):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM admin_logs")
    conn.commit()
    conn.close()
    
    log_admin_action(callback.from_user.id, "clear_logs", "all")
    await callback.answer("All logs cleared.", show_alert=True)
    await menu_logs(callback)

# =================================================================================
#                                    SETTINGS
# =================================================================================
@dp.callback_query_handler(lambda c: c.data == "menu_settings")
@admin_callback
async def menu_settings(callback: CallbackQuery):
    # Get bot info
    me = await bot.get_me()
    
    text = (
        "⚙️ **Bot Settings**\n\n"
        f"**Bot Username:** @{me.username}\n"
        f"**Bot ID:** `{me.id}`\n"
        f"**Admin IDs:** {', '.join(map(str, ADMIN_IDS))}\n"
        f"**Database:** `{DATABASE_PATH}`\n"
        f"**JWT Secret:** {'*' * 8}\n"
        f"**Backup Dir:** `{BACKUP_DIR}`\n"
        f"**Log File:** `{LOG_FILE}`\n\n"
        "**Actions:**"
    )
    
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🔄 Restart Bot", callback_data="settings_restart"),
        InlineKeyboardButton("📥 Download Logs", callback_data="settings_download_logs"),
        InlineKeyboardButton("🧪 Test Broadcast", callback_data="settings_test"),
        InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
    )
    
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "settings_restart")
@admin_callback
async def settings_restart(callback: CallbackQuery):
    await callback.answer("🔄 Restarting bot...", show_alert=True)
    # Graceful restart
    os.execl(sys.executable, sys.executable, *sys.argv)

@dp.callback_query_handler(lambda c: c.data == "settings_download_logs")
@admin_callback
async def settings_download_logs(callback: CallbackQuery):
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'rb') as f:
            await callback.message.reply_document(
                types.InputFile(f, filename=LOG_FILE),
                caption="📋 Bot log file."
            )
    else:
        await callback.answer("Log file not found.", show_alert=True)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "settings_test")
@admin_callback
async def settings_test(callback: CallbackQuery):
    await callback.answer("✅ Test successful!", show_alert=True)

# =================================================================================
#                                    SCHEDULED TASKS (ASYNC LOOP)
# =================================================================================
async def scheduled_worker():
    """Background task to run scheduled operations."""
    while True:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT task_name, interval_minutes, last_run, is_enabled FROM scheduled_tasks")
            tasks = c.fetchall()
            conn.close()
            
            now = datetime.utcnow()
            
            for task in tasks:
                if not task['is_enabled']:
                    continue
                
                last_run = datetime.fromisoformat(task['last_run']) if task['last_run'] else None
                interval = timedelta(minutes=task['interval_minutes'])
                
                if last_run is None or now - last_run >= interval:
                    # Execute task
                    if task['task_name'] == 'auto_cleanup':
                        await auto_cleanup()
                    elif task['task_name'] == 'auto_backup':
                        await auto_backup()
                    elif task['task_name'] == 'send_stats_report':
                        await send_stats_report()
                    
                    # Update last_run
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("UPDATE scheduled_tasks SET last_run = ? WHERE task_name = ?",
                              (now.isoformat(), task['task_name']))
                    conn.commit()
                    conn.close()
            
        except Exception as e:
            logger.exception(f"Scheduled worker error: {e}")
        
        await asyncio.sleep(60)  # check every minute

async def auto_cleanup():
    """Delete expired keys and deactivate stale instances."""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
    deleted_keys = c.rowcount
    c.execute("""
        UPDATE user_instances SET is_active = 0
        WHERE last_heartbeat < datetime('now', '-10 minutes')
    """)
    deactivated = c.rowcount
    conn.commit()
    conn.close()
    logger.info(f"Auto-cleanup: deleted {deleted_keys} keys, deactivated {deactivated} instances")

async def auto_backup():
    """Create automatic daily backup."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"auto_backup_{timestamp}.db")
    import shutil
    shutil.copy2(DATABASE_PATH, backup_file)
    logger.info(f"Auto-backup created: {backup_file}")

async def send_stats_report():
    """Send weekly statistics to admin."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM core_keys")
    total_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM user_instances WHERE is_active = 1")
    active_instances = c.fetchone()[0]
    conn.close()
    
    text = (
        "📊 **Weekly Statistics Report**\n\n"
        f"Total Keys: {total_keys}\n"
        f"Active Instances: {active_instances}\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(admin_id, text)
        except:
            pass

# =================================================================================
#                                    ERROR HANDLER
# =================================================================================
@dp.errors_handler()
async def errors_handler(update, exception):
    logger.exception(f"Update {update} caused error {exception}")
    return True

# =================================================================================
#                                    STARTUP & SHUTDOWN
# =================================================================================
async def on_startup(dp):
    logger.info("Starting Ultimate Admin Bot...")
    # Start scheduled tasks
    asyncio.create_task(scheduled_worker())

async def on_shutdown(dp):
    logger.info("Shutting down...")
    await dp.storage.close()
    await dp.storage.wait_closed()

# =================================================================================
#                                    MAIN
# =================================================================================
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("ULTIMATE ADMIN BOT STARTING")
    logger.info("=" * 60)
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup, on_shutdown=on_shutdown)
