#!/usr/bin/env python3
"""
================================================================================
                    ULTIMATE TELEGRAM ADMIN BOT – AIOGRAM V3
================================================================================
Hardcoded bot token & admin ID. Full inline keyboard navigation.
SQLite database. JWT key generation. 50+ admin features.
Built-in aiohttp health check server for Render.
No Flask. No contrib. No bloat.
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
import secrets
import shutil
from datetime import datetime, timedelta
from contextlib import closing
from functools import wraps
from typing import List, Dict, Tuple, Optional, Union

import jwt
import aiosqlite
from aiohttp import web
from aiogram import Bot, Dispatcher, types
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import ParseMode, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram import Router
from aiogram.filters import Command

# =================================================================================
#                                    CONFIGURATION
# =================================================================================
BOT_TOKEN = "8011804210:AAE--NiCSKKjbX4TC3nJVxuW64Fu53Ywh0w"
ADMIN_IDS = [8373846582]                # Only these users can use the bot
JWT_SECRET = "supersecretkey12345678901234567890123456789012"  # 32+ chars
DATABASE_PATH = "admin_bot.db"
BACKUP_DIR = "backups"
HEALTH_CHECK_PORT = int(os.environ.get("PORT", 10000))  # Render port

# =================================================================================
#                                    LOGGING SETUP
# =================================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("admin_bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

os.makedirs(BACKUP_DIR, exist_ok=True)

# =================================================================================
#                                    DATABASE INIT
# =================================================================================
async def init_db():
    """Create all SQLite tables asynchronously."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        await db.execute("""
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
        
        await db.execute("""
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
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT,
                target TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                user_id INTEGER PRIMARY KEY,
                reason TEXT,
                blocked_by INTEGER,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.execute("""
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
        
        await db.execute("""
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
        
        # Indexes
        await db.execute("CREATE INDEX IF NOT EXISTS idx_keys_issued_to ON core_keys(issued_to)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_keys_expiry ON core_keys(expiry)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_instances_user ON user_instances(user_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON admin_logs(timestamp)")
        
        await db.commit()
    logger.info("Database initialized.")

# =================================================================================
#                                    DATABASE HELPERS
# =================================================================================
async def get_db():
    """Return a new aiosqlite connection."""
    conn = await aiosqlite.connect(DATABASE_PATH)
    conn.row_factory = aiosqlite.Row
    return conn

async def log_admin_action(admin_id: int, action: str, target: str, details: str = ""):
    """Insert a log entry for admin actions."""
    async with await get_db() as db:
        await db.execute(
            "INSERT INTO admin_logs (admin_id, action, target, details) VALUES (?, ?, ?, ?)",
            (admin_id, action, target, details[:500])
        )
        await db.commit()

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
    return token, key_id, expiry

async def store_key(key_id: str, user_id: int, admin_id: int, max_instances: int, expiry: datetime, note: str, template: str = ""):
    """Store key in database."""
    async with await get_db() as db:
        await db.execute("""
            INSERT INTO core_keys
            (key_id, issued_to, issued_by, max_instances, expiry, note, template_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (key_id, user_id, admin_id, max_instances, expiry.isoformat(), note[:200], template[:50]))
        await db.commit()

def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and verify JWT. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

async def revoke_key(key_id: str, admin_id: int) -> bool:
    """Revoke a key and deactivate its instances."""
    async with await get_db() as db:
        key = await db.execute_fetchone("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
        if not key:
            return False
        await db.execute("DELETE FROM core_keys WHERE key_id = ?", (key_id,))
        await db.execute("UPDATE user_instances SET is_active = 0 WHERE key_id = ?", (key_id,))
        await log_admin_action(admin_id, "revoke", f"key:{key_id}", f"user:{key[1]}")
        await db.commit()
    return True

# =================================================================================
#                                    BOT INITIALIZATION (AIOGRAM V3)
# =================================================================================
bot = Bot(token=BOT_TOKEN, parse_mode=ParseMode.MARKDOWN)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)
router = Router()
dp.include_router(router)

# =================================================================================
#                                    HEALTH CHECK SERVER (AIOHTTP)
# =================================================================================
async def health_check(request):
    return web.Response(text="OK")

async def start_health_server():
    app = web.Application()
    app.router.add_get("/", health_check)
    app.router.add_get("/health", health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HEALTH_CHECK_PORT)
    await site.start()
    logger.info(f"Health check server running on port {HEALTH_CHECK_PORT}")

# =================================================================================
#                                    FSM STATES
# =================================================================================
class KeyGeneration(StatesGroup):
    waiting_user_id = State()
    waiting_days = State()
    waiting_max_instances = State()
    waiting_note = State()

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

class TemplateCreate(StatesGroup):
    waiting_name = State()
    waiting_days = State()
    waiting_max_instances = State()
    waiting_note = State()

class KeyRevoke(StatesGroup):
    waiting_key_id = State()

# =================================================================================
#                                    ADMIN ONLY DECORATOR
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
#                                    INLINE KEYBOARDS
# =================================================================================
def main_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🔑 Generate Key", callback_data="menu_genkey")
    builder.button(text="📋 List Keys", callback_data="menu_listkeys_0")
    builder.button(text="🔍 Search Keys", callback_data="menu_search")
    builder.button(text="📊 Statistics", callback_data="menu_stats")
    builder.button(text="🖥 Active Instances", callback_data="menu_instances_0")
    builder.button(text="🗑 Revoke Key", callback_data="menu_revoke")
    builder.button(text="✏️ Edit Key", callback_data="menu_edit")
    builder.button(text="📦 Key Templates", callback_data="menu_templates")
    builder.button(text="🚫 Blacklist", callback_data="menu_blacklist")
    builder.button(text="📢 Broadcast", callback_data="menu_broadcast")
    builder.button(text="🧹 Cleanup", callback_data="menu_cleanup")
    builder.button(text="💾 Backup/Restore", callback_data="menu_backup")
    builder.button(text="📤 Export Keys", callback_data="menu_export")
    builder.button(text="📜 Logs", callback_data="menu_logs_0")
    builder.button(text="⚙️ Settings", callback_data="menu_settings")
    builder.button(text="❌ Close", callback_data="menu_close")
    builder.adjust(2)
    return builder.as_markup()

def back_to_main_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    return builder.as_markup()

def confirm_keyboard(action: str, key_id: str = None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    callback_data = f"confirm_{action}"
    if key_id:
        callback_data += f"_{key_id}"
    builder.button(text="✅ Confirm", callback_data=callback_data)
    builder.button(text="❌ Cancel", callback_data="back_main")
    builder.adjust(2)
    return builder.as_markup()

def pagination_keyboard(base_callback: str, page: int, total_pages: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if page > 0:
        builder.button(text="◀️ Prev", callback_data=f"{base_callback}_{page-1}")
    builder.button(text=f"{page+1}/{total_pages}", callback_data="noop")
    if page < total_pages - 1:
        builder.button(text="Next ▶️", callback_data=f"{base_callback}_{page+1}")
    builder.adjust(3)
    builder.row(InlineKeyboardButton(text="🔙 Main Menu", callback_data="back_main"))
    return builder.as_markup()

# =================================================================================
#                                    PAGINATION HELPERS
# =================================================================================
async def paginate_keys(page: int = 0, per_page: int = 10, filter_expired: bool = False, user_id: int = None):
    """Return paginated list of keys and total pages."""
    async with await get_db() as db:
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
        cursor = await db.execute(query, params)
        keys = await cursor.fetchall()
        
        count_query = "SELECT COUNT(*) FROM core_keys"
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
        cursor = await db.execute(count_query, params[:len(params)-2] if user_id else [])
        total = (await cursor.fetchone())[0]
    return keys, total

# =================================================================================
#                                    COMMAND HANDLERS
# =================================================================================
@router.message(Command("start"))
@admin_only
async def cmd_start(message: types.Message):
    await message.answer(
        "🔐 **Ultimate Admin Control Panel**\n\n"
        "Welcome to the Core Key Management System.\n"
        "All functions are available via the inline keyboard below.",
        reply_markup=main_menu_keyboard()
    )
    await log_admin_action(message.from_user.id, "command", "/start")

@router.message(Command("cancel"))
@admin_only
async def cmd_cancel(message: types.Message, state: FSMContext):
    current_state = await state.get_state()
    if current_state is None:
        await message.reply("No active operation.")
        return
    await state.clear()
    await message.reply("❌ Operation cancelled.", reply_markup=main_menu_keyboard())

# =================================================================================
#                                    CALLBACK: MAIN MENU
# =================================================================================
@router.callback_query(lambda c: c.data == "back_main")
@admin_callback
async def back_to_main(callback: CallbackQuery, state: FSMContext = None):
    if state:
        await state.clear()
    await callback.message.edit_text(
        "🔐 **Ultimate Admin Control Panel**",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "menu_close")
@admin_callback
async def close_menu(callback: CallbackQuery):
    await callback.message.delete()
    await callback.answer("Menu closed.")

@router.callback_query(lambda c: c.data == "noop")
@admin_callback
async def noop(callback: CallbackQuery):
    await callback.answer()

# =================================================================================
#                                    KEY GENERATION
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_genkey")
@admin_callback
async def menu_genkey(callback: CallbackQuery):
    # Check if templates exist
    async with await get_db() as db:
        cursor = await db.execute("SELECT name FROM key_templates LIMIT 1")
        has_templates = await cursor.fetchone() is not None
    
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Manual Entry", callback_data="genkey_manual")
    if has_templates:
        builder.button(text="📋 Use Template", callback_data="genkey_template")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "🔑 **Generate Core Key**\n\nChoose input method:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "genkey_manual")
@admin_callback
async def genkey_manual(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyGeneration.waiting_user_id)
    await callback.message.edit_text(
        "🔑 **Manual Key Generation**\n\nEnter the Telegram **User ID** of the recipient:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "genkey_template")
@admin_callback
async def genkey_template(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("SELECT id, name, days, max_instances, note FROM key_templates ORDER BY name")
        templates = await cursor.fetchall()
    
    if not templates:
        await callback.message.edit_text(
            "❌ No templates found. Create one first in **Key Templates**.",
            reply_markup=main_menu_keyboard()
        )
        await callback.answer()
        return
    
    builder = InlineKeyboardBuilder()
    for t in templates:
        builder.button(text=f"{t['name']} ({t['days']}d, {t['max_instances']} inst)",
                       callback_data=f"genkey_usetemplate_{t['id']}")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "📋 **Select a Template:**",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data.startswith("genkey_usetemplate_"))
@admin_callback
async def genkey_use_template(callback: CallbackQuery, state: FSMContext):
    template_id = int(callback.data.split("_")[2])
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT name, days, max_instances, note FROM key_templates WHERE id = ?",
            (template_id,)
        )
        template = await cursor.fetchone()
    
    await state.update_data(
        days=template['days'],
        max_instances=template['max_instances'],
        note=template['note'],
        template_name=template['name']
    )
    await state.set_state(KeyGeneration.waiting_user_id)
    await callback.message.edit_text(
        f"📋 **Using Template:** {template['name']}\n"
        f"Days: {template['days']}, Max Instances: {template['max_instances']}\n\n"
        "Enter the Telegram **User ID**:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyGeneration.waiting_user_id)
@admin_only
async def process_user_id(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
    except ValueError:
        await message.reply("❌ Invalid ID. Please enter a numeric user ID.")
        return
    
    # Check blacklist
    async with await get_db() as db:
        cursor = await db.execute("SELECT reason FROM blacklist WHERE user_id = ?", (user_id,))
        blocked = await cursor.fetchone()
    if blocked:
        await message.reply(
            f"⛔ This user is **blacklisted**.\nReason: {blocked['reason']}\n\n"
            "You must remove them from blacklist first.",
            reply_markup=main_menu_keyboard()
        )
        await state.clear()
        return
    
    await state.update_data(user_id=user_id)
    data = await state.get_data()
    if 'days' in data:
        await state.set_state(KeyGeneration.waiting_note)
        await message.reply(
            "📝 Enter an optional **note** for this key (or send `-` to skip):",
            reply_markup=back_to_main_keyboard()
        )
    else:
        await state.set_state(KeyGeneration.waiting_days)
        await message.reply(
            "📅 Enter the number of **days** this key should be valid:",
            reply_markup=back_to_main_keyboard()
        )

@router.message(KeyGeneration.waiting_days)
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
    await state.set_state(KeyGeneration.waiting_max_instances)
    await message.reply(
        "🖥 Enter the **maximum number of concurrent instances** (e.g., 3):",
        reply_markup=back_to_main_keyboard()
    )

@router.message(KeyGeneration.waiting_max_instances)
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
    await state.set_state(KeyGeneration.waiting_note)
    await message.reply(
        "📝 Enter an optional **note** for this key (or send `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@router.message(KeyGeneration.waiting_note)
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
    await store_key(key_id, user_id, message.from_user.id, max_inst, expiry, note, template)
    
    await log_admin_action(
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
    
    builder = InlineKeyboardBuilder()
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    await state.clear()
    await message.reply(text, reply_markup=builder.as_markup())

# =================================================================================
#                                    LIST KEYS WITH PAGINATION
# =================================================================================
@router.callback_query(lambda c: c.data.startswith("menu_listkeys_"))
@admin_callback
async def menu_listkeys(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    keys, total = await paginate_keys(page, per_page=8)
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
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# =================================================================================
#                                    SEARCH KEYS
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_search")
@admin_callback
async def menu_search(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeySearch.waiting_query)
    await callback.message.edit_text(
        "🔍 **Search Keys**\n\nEnter a **User ID** or **Key ID** (or part of it):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeySearch.waiting_query)
@admin_only
async def process_search(message: types.Message, state: FSMContext):
    query = message.text.strip()
    async with await get_db() as db:
        try:
            user_id = int(query)
            cursor = await db.execute("""
                SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
                FROM core_keys WHERE issued_to = ?
                ORDER BY created_at DESC LIMIT 20
            """, (user_id,))
        except ValueError:
            cursor = await db.execute("""
                SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
                FROM core_keys WHERE key_id LIKE ?
                ORDER BY created_at DESC LIMIT 20
            """, (f"%{query}%",))
        keys = await cursor.fetchall()
    
    if not keys:
        await message.reply("❌ No matching keys found.", reply_markup=main_menu_keyboard())
        await state.clear()
        return
    
    text = f"🔍 **Search Results** for `{query}`:\n\n"
    for key in keys[:10]:
        text += (
            f"**ID:** `{key['key_id'][:8]}...`\n"
            f"👤 User: `{key['issued_to']}`\n"
            f"🔄 Used: {key['usage_count']}/{key['max_instances']}\n"
            f"📅 Exp: {key['expiry'][:10]}\n\n"
        )
    if len(keys) > 10:
        text += f"... and {len(keys)-10} more.\n"
    
    await state.clear()
    await message.reply(text, reply_markup=main_menu_keyboard())

# =================================================================================
#                                    STATISTICS
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_stats")
@admin_callback
async def menu_stats(callback: CallbackQuery):
    async with await get_db() as db:
        total_keys = (await db.execute_fetchone("SELECT COUNT(*) FROM core_keys"))[0]
        expired_keys = (await db.execute_fetchone("SELECT COUNT(*) FROM core_keys WHERE expiry < datetime('now')"))[0]
        active_keys = (await db.execute_fetchone("SELECT COUNT(*) FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')"))[0]
        active_instances = (await db.execute_fetchone("SELECT COUNT(*) FROM user_instances WHERE is_active = 1"))[0]
        total_instances = (await db.execute_fetchone("SELECT COUNT(*) FROM user_instances"))[0]
        total_usage = (await db.execute_fetchone("SELECT SUM(usage_count) FROM core_keys"))[0] or 0
        unique_users = (await db.execute_fetchone("SELECT COUNT(DISTINCT issued_to) FROM core_keys"))[0]
        expiring_soon = (await db.execute_fetchone("""
            SELECT COUNT(*) FROM core_keys 
            WHERE expiry < datetime('now', '+7 days') AND expiry > datetime('now')
        """))[0]
    
    text = (
        "📊 **Admin Statistics**\n\n"
        f"🔑 **Total Keys Issued:** `{total_keys}`\n"
        f"✅ **Active Keys:** `{active_keys}`\n"
        f"⚠️ **Expired Keys:** `{expired_keys}`\n"
        f"⏳ **Expiring in 7 days:** `{expiring_soon}`\n"
        f"🖥 **Active Instances:** `{active_instances}`\n"
        f"📦 **Total Instances:** `{total_instances}`\n"
        f"🗳 **Total Key Usage:** `{total_usage}`\n"
        f"👥 **Unique Users:** `{unique_users}`\n"
    )
    
    await callback.message.edit_text(text, reply_markup=main_menu_keyboard())
    await callback.answer()

# =================================================================================
#                                    ACTIVE INSTANCES
# =================================================================================
@router.callback_query(lambda c: c.data.startswith("menu_instances_"))
@admin_callback
async def menu_instances(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    per_page = 8
    
    async with await get_db() as db:
        cursor = await db.execute("""
            SELECT i.user_id, i.port, i.last_heartbeat, i.ip_address, i.version,
                   k.key_id, k.issued_to, k.expiry
            FROM user_instances i
            JOIN core_keys k ON i.key_id = k.key_id
            WHERE i.is_active = 1
            ORDER BY i.last_heartbeat DESC
            LIMIT ? OFFSET ?
        """, (per_page, page * per_page))
        rows = await cursor.fetchall()
        
        total = (await db.execute_fetchone("SELECT COUNT(*) FROM user_instances WHERE is_active = 1"))[0]
    
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
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# =================================================================================
#                                    REVOKE KEY
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_revoke")
@admin_callback
async def menu_revoke(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyRevoke.waiting_key_id)
    await callback.message.edit_text(
        "🗑 **Revoke Core Key**\n\n"
        "Send the **Key ID** or the full **JWT token**.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyRevoke.waiting_key_id)
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
    
    async with await get_db() as db:
        key = await db.execute_fetchone("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
    
    if not key:
        await message.reply("❌ Key not found.")
        await state.clear()
        return
    
    await state.update_data(key_id=key_id)
    await message.reply(
        f"⚠️ **Are you sure?**\n\n"
        f"This will revoke key `{key_id[:8]}...` for user `{key[1]}`.\n"
        f"All active instances will be deactivated.",
        reply_markup=confirm_keyboard("revoke", key_id)
    )
    await state.clear()

@router.callback_query(lambda c: c.data.startswith("confirm_revoke_"))
@admin_callback
async def confirm_revoke(callback: CallbackQuery):
    key_id = callback.data.split("_")[2]
    success = await revoke_key(key_id, callback.from_user.id)
    if success:
        await callback.message.edit_text(
            f"✅ Key `{key_id[:8]}...` revoked and instances deactivated.",
            reply_markup=main_menu_keyboard()
        )
    else:
        await callback.message.edit_text("❌ Key not found.", reply_markup=main_menu_keyboard())
    await callback.answer()

# =================================================================================
#                                    KEY EDIT (SIMPLIFIED)
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_edit")
@admin_callback
async def menu_edit(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyEdit.waiting_key_id)
    await callback.message.edit_text(
        "✏️ **Edit Core Key**\n\nSend the **Key ID** or full **JWT token**.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyEdit.waiting_key_id)
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
    
    async with await get_db() as db:
        key = await db.execute_fetchone("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
    
    if not key:
        await message.reply("❌ Key not found.")
        await state.clear()
        return
    
    await state.update_data(key_id=key_id)
    
    builder = InlineKeyboardBuilder()
    builder.button(text="🖥 Change Max Instances", callback_data="edit_maxinst")
    builder.button(text="📅 Extend Expiry", callback_data="edit_extend")
    builder.button(text="📝 Edit Note", callback_data="edit_note")
    builder.button(text="🔙 Cancel", callback_data="back_main")
    builder.adjust(2)
    
    await message.reply(
        f"✏️ **Editing Key** `{key_id[:8]}...`\n"
        f"Current: Max Instances={key['max_instances']}, Expires={key['expiry'][:10]}, Note={key['note'] or '—'}\n\n"
        "What would you like to change?",
        reply_markup=builder.as_markup()
    )
    await state.set_state(KeyEdit.waiting_new_max_instances)

@router.callback_query(lambda c: c.data == "edit_maxinst", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_maxinst_prompt(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyEdit.waiting_new_max_instances)
    await callback.message.edit_text(
        "🖥 Enter the **new maximum number of instances**:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyEdit.waiting_new_max_instances)
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
    
    async with await get_db() as db:
        await db.execute("UPDATE core_keys SET max_instances = ? WHERE key_id = ?", (new_max, key_id))
        await db.commit()
    
    await log_admin_action(message.from_user.id, "edit_key", f"key:{key_id}", f"max_instances={new_max}")
    await state.clear()
    await message.reply(f"✅ Max instances updated to {new_max}.", reply_markup=main_menu_keyboard())

@router.callback_query(lambda c: c.data == "edit_extend", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_extend_prompt(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyEdit.waiting_extend_days)
    await callback.message.edit_text(
        "📅 Enter the **number of days to extend** the key:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyEdit.waiting_extend_days)
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
    
    async with await get_db() as db:
        row = await db.execute_fetchone("SELECT expiry FROM core_keys WHERE key_id = ?", (key_id,))
        if not row:
            await message.reply("❌ Key not found.")
            await state.clear()
            return
        current_expiry = datetime.fromisoformat(row[0])
        new_expiry = current_expiry + timedelta(days=days)
        await db.execute("UPDATE core_keys SET expiry = ? WHERE key_id = ?", (new_expiry.isoformat(), key_id))
        await db.commit()
    
    await log_admin_action(message.from_user.id, "extend_key", f"key:{key_id}", f"+{days} days")
    await state.clear()
    await message.reply(f"✅ Key extended until {new_expiry.strftime('%Y-%m-%d')}.", reply_markup=main_menu_keyboard())

@router.callback_query(lambda c: c.data == "edit_note", state=KeyEdit.waiting_new_max_instances)
@admin_callback
async def edit_note_prompt(callback: CallbackQuery, state: FSMContext):
    await state.set_state(KeyEdit.waiting_new_note)
    await callback.message.edit_text(
        "📝 Enter the **new note** for this key (or `-` to clear):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(KeyEdit.waiting_new_note)
@admin_only
async def edit_note_save(message: types.Message, state: FSMContext):
    new_note = message.text.strip()
    if new_note == "-":
        new_note = ""
    
    data = await state.get_data()
    key_id = data['key_id']
    
    async with await get_db() as db:
        await db.execute("UPDATE core_keys SET note = ? WHERE key_id = ?", (new_note[:200], key_id))
        await db.commit()
    
    await log_admin_action(message.from_user.id, "edit_key", f"key:{key_id}", f"note updated")
    await state.clear()
    await message.reply(f"✅ Note updated.", reply_markup=main_menu_keyboard())

# =================================================================================
#                                    KEY TEMPLATES
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_templates")
@admin_callback
async def menu_templates(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("SELECT id, name, days, max_instances, note, created_at FROM key_templates ORDER BY name")
        templates = await cursor.fetchall()
    
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Create Template", callback_data="template_create")
    if templates:
        builder.button(text="🗑 Delete Template", callback_data="template_delete")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    text = "📦 **Key Templates**\n\n"
    if templates:
        for t in templates:
            text += f"• **{t['name']}** – {t['days']}d, {t['max_instances']} inst\n"
            if t['note']:
                text += f"  Note: {t['note']}\n"
    else:
        text += "No templates yet. Create one!"
    
    await callback.message.edit_text(text, reply_markup=builder.as_markup())
    await callback.answer()

@router.callback_query(lambda c: c.data == "template_create")
@admin_callback
async def template_create_start(callback: CallbackQuery, state: FSMContext):
    await state.set_state(TemplateCreate.waiting_name)
    await callback.message.edit_text(
        "📝 **Create Key Template**\n\nEnter a **name** for this template (e.g., 'Basic', 'Premium'):",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(TemplateCreate.waiting_name)
@admin_only
async def template_create_name(message: types.Message, state: FSMContext):
    name = message.text.strip()
    if not name:
        await message.reply("❌ Name cannot be empty.")
        return
    
    async with await get_db() as db:
        existing = await db.execute_fetchone("SELECT name FROM key_templates WHERE name = ?", (name,))
        if existing:
            await message.reply("❌ A template with that name already exists. Choose another name.")
            return
    
    await state.update_data(name=name)
    await state.set_state(TemplateCreate.waiting_days)
    await message.reply(
        "📅 Enter the **number of days** this key should be valid:",
        reply_markup=back_to_main_keyboard()
    )

@router.message(TemplateCreate.waiting_days)
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
    await state.set_state(TemplateCreate.waiting_max_instances)
    await message.reply(
        "🖥 Enter the **maximum number of instances**:",
        reply_markup=back_to_main_keyboard()
    )

@router.message(TemplateCreate.waiting_max_instances)
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
    await state.set_state(TemplateCreate.waiting_note)
    await message.reply(
        "📝 Enter an optional **note** for this template (or `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@router.message(TemplateCreate.waiting_note)
@admin_only
async def template_create_note(message: types.Message, state: FSMContext):
    note = message.text.strip()
    if note == "-":
        note = ""
    
    data = await state.get_data()
    name = data['name']
    days = data['days']
    max_inst = data['max_instances']
    
    async with await get_db() as db:
        await db.execute(
            "INSERT INTO key_templates (name, days, max_instances, note, created_by) VALUES (?, ?, ?, ?, ?)",
            (name, days, max_inst, note[:200], message.from_user.id)
        )
        await db.commit()
    
    await log_admin_action(message.from_user.id, "create_template", f"template:{name}")
    await state.clear()
    await message.reply(f"✅ Template '{name}' created.", reply_markup=main_menu_keyboard())

@router.callback_query(lambda c: c.data == "template_delete")
@admin_callback
async def template_delete_menu(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("SELECT id, name FROM key_templates ORDER BY name")
        templates = await cursor.fetchall()
    
    if not templates:
        await callback.answer("No templates to delete.", show_alert=True)
        return
    
    builder = InlineKeyboardBuilder()
    for t in templates:
        builder.button(text=f"❌ {t['name']}", callback_data=f"template_del_{t['id']}")
    builder.button(text="🔙 Back", callback_data="menu_templates")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "🗑 **Delete Template**\n\nSelect a template to delete:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data.startswith("template_del_"))
@admin_callback
async def template_delete_execute(callback: CallbackQuery):
    template_id = int(callback.data.split("_")[2])
    async with await get_db() as db:
        name_row = await db.execute_fetchone("SELECT name FROM key_templates WHERE id = ?", (template_id,))
        if name_row:
            await db.execute("DELETE FROM key_templates WHERE id = ?", (template_id,))
            await db.commit()
            await log_admin_action(callback.from_user.id, "delete_template", f"template:{name_row[0]}")
            await callback.answer(f"Template '{name_row[0]}' deleted.", show_alert=True)
        else:
            await callback.answer("Template not found.", show_alert=True)
    await menu_templates(callback)

# =================================================================================
#                                    BLACKLIST
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_blacklist")
@admin_callback
async def menu_blacklist(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("SELECT user_id, reason, blocked_at FROM blacklist ORDER BY blocked_at DESC LIMIT 15")
        blocked = await cursor.fetchall()
    
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Add to Blacklist", callback_data="blacklist_add")
    if blocked:
        builder.button(text="➖ Remove from Blacklist", callback_data="blacklist_remove")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    text = "🚫 **Blacklist**\n\n"
    if blocked:
        for b in blocked:
            text += f"• User `{b['user_id']}` – {b['reason'] or 'No reason'} ({b['blocked_at'][:10]})\n"
    else:
        text += "No users blacklisted."
    
    await callback.message.edit_text(text, reply_markup=builder.as_markup())
    await callback.answer()

@router.callback_query(lambda c: c.data == "blacklist_add")
@admin_callback
async def blacklist_add_prompt(callback: CallbackQuery, state: FSMContext):
    await state.set_state(BlacklistAdd.waiting_user_id)
    await callback.message.edit_text(
        "🚫 **Add to Blacklist**\n\nEnter the **User ID** to block:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(BlacklistAdd.waiting_user_id)
@admin_only
async def blacklist_add_user(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text.strip())
    except ValueError:
        await message.reply("❌ Invalid User ID.")
        return
    
    await state.update_data(user_id=user_id)
    await state.set_state(BlacklistAdd.waiting_reason)
    await message.reply(
        "📝 Enter the **reason** for blacklisting (or send `-` to skip):",
        reply_markup=back_to_main_keyboard()
    )

@router.message(BlacklistAdd.waiting_reason)
@admin_only
async def blacklist_add_reason(message: types.Message, state: FSMContext):
    reason = message.text.strip()
    if reason == "-":
        reason = ""
    
    data = await state.get_data()
    user_id = data['user_id']
    
    async with await get_db() as db:
        await db.execute(
            "INSERT OR REPLACE INTO blacklist (user_id, reason, blocked_by) VALUES (?, ?, ?)",
            (user_id, reason[:200], message.from_user.id)
        )
        await db.commit()
    
    await log_admin_action(message.from_user.id, "blacklist_add", f"user:{user_id}", reason[:100])
    await state.clear()
    await message.reply(f"✅ User `{user_id}` added to blacklist.", reply_markup=main_menu_keyboard())

@router.callback_query(lambda c: c.data == "blacklist_remove")
@admin_callback
async def blacklist_remove_prompt(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("SELECT user_id FROM blacklist")
        users = await cursor.fetchall()
    
    if not users:
        await callback.answer("Blacklist is empty.", show_alert=True)
        return
    
    builder = InlineKeyboardBuilder()
    for u in users:
        builder.button(text=f"❌ {u['user_id']}", callback_data=f"blacklist_remove_{u['user_id']}")
    builder.button(text="🔙 Back", callback_data="menu_blacklist")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "➖ **Remove from Blacklist**\n\nSelect a user to unblock:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data.startswith("blacklist_remove_"))
@admin_callback
async def blacklist_remove_execute(callback: CallbackQuery):
    user_id = int(callback.data.split("_")[2])
    async with await get_db() as db:
        await db.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))
        await db.commit()
    
    await log_admin_action(callback.from_user.id, "blacklist_remove", f"user:{user_id}")
    await callback.answer(f"User {user_id} removed from blacklist.", show_alert=True)
    await menu_blacklist(callback)

# =================================================================================
#                                    BROADCAST
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_broadcast")
@admin_callback
async def menu_broadcast(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Broadcast.waiting_message)
    await callback.message.edit_text(
        "📢 **Broadcast Message**\n\n"
        "Send the message you want to broadcast to **all users with active keys**.\n"
        "You can use Markdown formatting.\n\n"
        "To cancel, send /cancel.",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

@router.message(Broadcast.waiting_message)
@admin_only
async def broadcast_preview(message: types.Message, state: FSMContext):
    msg_text = message.text
    await state.update_data(message=msg_text)
    
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT DISTINCT issued_to FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')"
        )
        recipients = [row[0] for row in await cursor.fetchall()]
    
    await state.update_data(recipients=recipients)
    
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Send Now", callback_data="broadcast_send")
    builder.button(text="✏️ Edit Message", callback_data="broadcast_edit")
    builder.button(text="❌ Cancel", callback_data="back_main")
    builder.adjust(2)
    
    await message.reply(
        f"📢 **Broadcast Preview**\n\n"
        f"Recipients: {len(recipients)} users\n\n"
        f"Message:\n{msg_text}\n\n"
        f"Send?",
        reply_markup=builder.as_markup()
    )
    await state.set_state(Broadcast.waiting_confirm)

@router.callback_query(lambda c: c.data == "broadcast_send", state=Broadcast.waiting_confirm)
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
    
    async with await get_db() as db:
        await db.execute(
            "INSERT INTO broadcast_history (admin_id, message, recipients, successful, failed) VALUES (?, ?, ?, ?, ?)",
            (callback.from_user.id, msg_text[:200], len(recipients), sent, failed)
        )
        await db.commit()
    
    await log_admin_action(callback.from_user.id, "broadcast", f"recipients:{len(recipients)}", f"sent:{sent} failed:{failed}")
    await state.clear()
    await callback.message.edit_text(
        f"✅ **Broadcast sent**\n\n📨 Delivered: {sent}\n❌ Failed: {failed}",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "broadcast_edit", state=Broadcast.waiting_confirm)
@admin_callback
async def broadcast_edit(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Broadcast.waiting_message)
    await callback.message.edit_text(
        "📢 **Edit Broadcast Message**\n\nSend the new message:",
        reply_markup=back_to_main_keyboard()
    )
    await callback.answer()

# =================================================================================
#                                    CLEANUP
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_cleanup")
@admin_callback
async def menu_cleanup(callback: CallbackQuery):
    builder = InlineKeyboardBuilder()
    builder.button(text="🗑 Delete Expired Keys", callback_data="cleanup_expired")
    builder.button(text="💤 Deactivate Stale Instances", callback_data="cleanup_stale")
    builder.button(text="🧹 Full Cleanup", callback_data="cleanup_full")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    await callback.message.edit_text(
        "🧹 **Cleanup Tools**\n\nChoose an action:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "cleanup_expired")
@admin_callback
async def cleanup_expired(callback: CallbackQuery):
    async with await get_db() as db:
        await db.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
        deleted = db.total_changes
        await db.commit()
        await log_admin_action(callback.from_user.id, "cleanup", "expired_keys", f"deleted:{deleted}")
    
    await callback.answer(f"✅ {deleted} expired keys deleted.", show_alert=True)
    await menu_cleanup(callback)

@router.callback_query(lambda c: c.data == "cleanup_stale")
@admin_callback
async def cleanup_stale(callback: CallbackQuery):
    async with await get_db() as db:
        await db.execute("""
            UPDATE user_instances SET is_active = 0
            WHERE last_heartbeat < datetime('now', '-10 minutes')
        """)
        deactivated = db.total_changes
        await db.commit()
        await log_admin_action(callback.from_user.id, "cleanup", "stale_instances", f"deactivated:{deactivated}")
    
    await callback.answer(f"✅ {deactivated} stale instances deactivated.", show_alert=True)
    await menu_cleanup(callback)

@router.callback_query(lambda c: c.data == "cleanup_full")
@admin_callback
async def cleanup_full(callback: CallbackQuery):
    async with await get_db() as db:
        await db.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
        deleted_keys = db.total_changes
        await db.execute("""
            UPDATE user_instances SET is_active = 0
            WHERE last_heartbeat < datetime('now', '-10 minutes')
        """)
        deactivated = db.total_changes
        await db.commit()
        await log_admin_action(callback.from_user.id, "cleanup", "full", f"keys:{deleted_keys} instances:{deactivated}")
    
    await callback.answer(f"✅ Full cleanup: {deleted_keys} keys, {deactivated} instances.", show_alert=True)
    await menu_cleanup(callback)

# =================================================================================
#                                    BACKUP & RESTORE
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_backup")
@admin_callback
async def menu_backup(callback: CallbackQuery):
    builder = InlineKeyboardBuilder()
    builder.button(text="💾 Create Backup", callback_data="backup_create")
    builder.button(text="📂 List Backups", callback_data="backup_list")
    builder.button(text="🔄 Restore", callback_data="backup_restore")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    await callback.message.edit_text(
        "💾 **Backup & Restore**\n\nManage database backups.",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "backup_create")
@admin_callback
async def backup_create(callback: CallbackQuery):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"backup_{timestamp}.db")
    
    shutil.copy2(DATABASE_PATH, backup_file)
    
    metadata = {
        "timestamp": timestamp,
        "created_by": callback.from_user.id,
        "database": DATABASE_PATH,
    }
    with open(backup_file + ".meta.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    await log_admin_action(callback.from_user.id, "backup", f"file:{backup_file}")
    
    with open(backup_file, 'rb') as f:
        await callback.message.reply_document(
            types.BufferedInputFile(f.read(), filename=f"backup_{timestamp}.db"),
            caption=f"✅ Backup created: `{backup_file}`"
        )
    await callback.answer("Backup file sent.", show_alert=True)

@router.callback_query(lambda c: c.data == "backup_list")
@admin_callback
async def backup_list(callback: CallbackQuery):
    backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
    db_backups = [f for f in backups if f.endswith('.db')][:20]
    
    if not db_backups:
        await callback.message.edit_text("No backups found.", reply_markup=main_menu_keyboard())
        await callback.answer()
        return
    
    text = "📂 **Available Backups**\n\n"
    for b in db_backups[:10]:
        size = os.path.getsize(os.path.join(BACKUP_DIR, b))
        text += f"• `{b}` ({size} bytes)\n"
    
    builder = InlineKeyboardBuilder()
    for b in db_backups[:5]:
        builder.button(text=f"📥 {b[:20]}", callback_data=f"backup_download_{b}")
    builder.button(text="🔙 Back", callback_data="menu_backup")
    builder.adjust(1)
    
    await callback.message.edit_text(text, reply_markup=builder.as_markup())
    await callback.answer()

@router.callback_query(lambda c: c.data.startswith("backup_download_"))
@admin_callback
async def backup_download(callback: CallbackQuery):
    filename = callback.data[16:]
    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        await callback.answer("File not found.", show_alert=True)
        return
    
    with open(filepath, 'rb') as f:
        await callback.message.reply_document(
            types.BufferedInputFile(f.read(), filename=filename),
            caption=f"📥 Backup: {filename}"
        )
    await callback.answer()

@router.callback_query(lambda c: c.data == "backup_restore")
@admin_callback
async def backup_restore_prompt(callback: CallbackQuery):
    backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
    db_backups = [f for f in backups if f.endswith('.db')][:10]
    
    if not db_backups:
        await callback.message.edit_text("No backups to restore.", reply_markup=main_menu_keyboard())
        await callback.answer()
        return
    
    builder = InlineKeyboardBuilder()
    for b in db_backups:
        builder.button(text=f"⚠️ Restore {b[:20]}", callback_data=f"backup_restore_confirm_{b}")
    builder.button(text="🔙 Cancel", callback_data="menu_backup")
    builder.adjust(1)
    
    await callback.message.edit_text(
        "⚠️ **Restore Database**\n\n"
        "This will overwrite the current database with the selected backup.\n"
        "**This action is irreversible!**\n\n"
        "Select a backup:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data.startswith("backup_restore_confirm_"))
@admin_callback
async def backup_restore_execute(callback: CallbackQuery):
    filename = callback.data[23:]
    filepath = os.path.join(BACKUP_DIR, filename)
    
    if not os.path.exists(filepath):
        await callback.answer("Backup file not found.", show_alert=True)
        return
    
    # Pre-restore backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_restore = os.path.join(BACKUP_DIR, f"pre_restore_{timestamp}.db")
    shutil.copy2(DATABASE_PATH, pre_restore)
    
    # Restore
    shutil.copy2(filepath, DATABASE_PATH)
    
    await log_admin_action(callback.from_user.id, "restore", f"from:{filename}", f"pre_backup:{pre_restore}")
    
    await callback.message.edit_text(
        f"✅ Database restored from `{filename}`.\n"
        f"A backup of the previous database was saved as `{pre_restore}`.",
        reply_markup=main_menu_keyboard()
    )
    await callback.answer()

# =================================================================================
#                                    EXPORT KEYS
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_export")
@admin_callback
async def menu_export(callback: CallbackQuery):
    builder = InlineKeyboardBuilder()
    builder.button(text="📄 Export as JSON", callback_data="export_json")
    builder.button(text="📊 Export as CSV", callback_data="export_csv")
    builder.button(text="📋 Export Active Keys", callback_data="export_active")
    builder.button(text="📤 Export Full DB", callback_data="export_db")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    await callback.message.edit_text(
        "📤 **Export Data**\n\nChoose format:",
        reply_markup=builder.as_markup()
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "export_json")
@admin_callback
async def export_json(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("""
            SELECT key_id, issued_to, issued_by, max_instances, usage_count, expiry, note, created_at, is_active
            FROM core_keys ORDER BY created_at DESC
        """)
        rows = await cursor.fetchall()
    
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
    
    await callback.message.reply_document(
        types.BufferedInputFile(json_str.encode(), filename=filename),
        caption=f"📄 Exported {len(data)} keys."
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "export_csv")
@admin_callback
async def export_csv(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("""
            SELECT key_id, issued_to, max_instances, usage_count, expiry, note, created_at
            FROM core_keys ORDER BY created_at DESC
        """)
        rows = await cursor.fetchall()
    
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
        types.BufferedInputFile(csv_data, filename=filename),
        caption=f"📊 Exported {len(rows)} keys."
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "export_active")
@admin_callback
async def export_active(callback: CallbackQuery):
    async with await get_db() as db:
        cursor = await db.execute("""
            SELECT key_id, issued_to, max_instances, usage_count, expiry, note
            FROM core_keys WHERE is_active = 1 AND expiry > datetime('now')
            ORDER BY created_at DESC
        """)
        rows = await cursor.fetchall()
    
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
        types.BufferedInputFile(csv_data, filename=filename),
        caption=f"📋 Exported {len(rows)} active keys."
    )
    await callback.answer()

@router.callback_query(lambda c: c.data == "export_db")
@admin_callback
async def export_db(callback: CallbackQuery):
    with open(DATABASE_PATH, 'rb') as f:
        await callback.message.reply_document(
            types.BufferedInputFile(f.read(), filename=f"admin_bot_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"),
            caption="📦 Full database export."
        )
    await callback.answer()

# =================================================================================
#                                    LOGS VIEWER
# =================================================================================
@router.callback_query(lambda c: c.data.startswith("menu_logs_"))
@admin_callback
async def menu_logs(callback: CallbackQuery):
    page = int(callback.data.split("_")[2])
    per_page = 15
    
    async with await get_db() as db:
        cursor = await db.execute("""
            SELECT timestamp, admin_id, action, target, details
            FROM admin_logs
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (per_page, page * per_page))
        logs = await cursor.fetchall()
        
        total = (await db.execute_fetchone("SELECT COUNT(*) FROM admin_logs"))[0]
    
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
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# =================================================================================
#                                    SETTINGS
# =================================================================================
@router.callback_query(lambda c: c.data == "menu_settings")
@admin_callback
async def menu_settings(callback: CallbackQuery):
    me = await bot.get_me()
    
    text = (
        "⚙️ **Bot Settings**\n\n"
        f"**Bot Username:** @{me.username}\n"
        f"**Bot ID:** `{me.id}`\n"
        f"**Admin IDs:** {', '.join(map(str, ADMIN_IDS))}\n"
        f"**Database:** `{DATABASE_PATH}`\n"
        f"**Backup Dir:** `{BACKUP_DIR}`\n"
        f"**Health Port:** `{HEALTH_CHECK_PORT}`\n\n"
        "**Actions:**"
    )
    
    builder = InlineKeyboardBuilder()
    builder.button(text="📥 Download Logs", callback_data="settings_download_logs")
    builder.button(text="🧪 Test", callback_data="settings_test")
    builder.button(text="🔙 Main Menu", callback_data="back_main")
    builder.adjust(2)
    
    await callback.message.edit_text(text, reply_markup=builder.as_markup())
    await callback.answer()

@router.callback_query(lambda c: c.data == "settings_download_logs")
@admin_callback
async def settings_download_logs(callback: CallbackQuery):
    if os.path.exists("admin_bot.log"):
        with open("admin_bot.log", 'rb') as f:
            await callback.message.reply_document(
                types.BufferedInputFile(f.read(), filename="admin_bot.log"),
                caption="📋 Bot log file."
            )
    else:
        await callback.answer("Log file not found.", show_alert=True)
    await callback.answer()

@router.callback_query(lambda c: c.data == "settings_test")
@admin_callback
async def settings_test(callback: CallbackQuery):
    await callback.answer("✅ Test successful!", show_alert=True)

# =================================================================================
#                                    ERROR HANDLER
# =================================================================================
@dp.errors()
async def errors_handler(event: types.ErrorEvent):
    logger.exception(f"Update {event.update} caused error {event.exception}")
    return True

# =================================================================================
#                                    STARTUP
# =================================================================================
async def on_startup():
    await init_db()
    asyncio.create_task(start_health_server())
    logger.info("Bot started and health server running.")

async def main():
    dp.startup.register(on_startup)
    await dp.start_polling(bot)

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("ULTIMATE ADMIN BOT STARTING (AIOGRAM V3)")
    logger.info("=" * 60)
    asyncio.run(main())
