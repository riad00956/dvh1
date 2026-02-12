#!/usr/bin/env python3
"""
Advanced Multi-User Telegram Voting Bot
Single file – runs as Admin Bot or User Bot based on BOT_MODE.
"""

import os
import sys
import json
import uuid
import time
import threading
import logging
import sqlite3
import socket
import csv
import io
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

# -------------------- Core Dependencies --------------------
try:
    import jwt
    import requests
    from dotenv import load_dotenv
    from flask import Flask, render_template_string, jsonify, request as flask_request, send_file
    from aiogram import Bot, Dispatcher, types
    from aiogram.contrib.middlewares.logging import LoggingMiddleware
    from aiogram.types import ParseMode, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
    from aiogram.utils import executor
    from aiogram.contrib.fsm_storage.memory import MemoryStorage
    from aiogram.dispatcher import FSMContext
    from aiogram.dispatcher.filters.state import State, StatesGroup
    import asyncpg  # only used in admin mode
    from aiohttp import web  # only used in admin mode
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install required packages:")
    print("pip install pyjwt requests python-dotenv flask aiogram asyncpg aiohttp")
    sys.exit(1)

# -------------------- Environment & Configuration --------------------
load_dotenv()

BOT_MODE = os.getenv("BOT_MODE", "user").lower()  # "admin" or "user"
BOT_TOKEN = os.getenv("BOT_TOKEN")
USER_ID = int(os.getenv("USER_ID", "0"))  # Only for user bot
CORE_KEY = os.getenv("CORE_KEY", "")       # Only for user bot
ADMIN_API_URL = os.getenv("ADMIN_API_URL", "")  # Only for user bot
PORT = int(os.getenv("PORT", "8080"))      # Port for Flask (user) or webhook (admin)
ADMIN_JWT_SECRET = os.getenv("ADMIN_JWT_SECRET", "change-me")  # Admin only
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///admin.db")  # Admin only
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")  # Admin only
ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "").split(","))) if os.getenv("ADMIN_IDS") else []

# -------------------- Logging Setup --------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'bot_{BOT_MODE}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# -------------------- Shared Utilities --------------------
def is_port_in_use(port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(('127.0.0.1', port)) == 0

def create_backup_keyboard():
    return InlineKeyboardMarkup().add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))

# -------------------- MODE: ADMIN BOT --------------------
if BOT_MODE == "admin":
    logger.info("Starting in ADMIN mode")

    # ---------- Database (PostgreSQL or SQLite) ----------
    if DATABASE_URL.startswith("postgresql"):
        # PostgreSQL
        async def create_db_pool():
            return await asyncpg.create_pool(DATABASE_URL)
        
        async def init_db(pool):
            async with pool.acquire() as conn:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS core_keys (
                        key_id UUID PRIMARY KEY,
                        issued_to BIGINT,
                        issued_by BIGINT,
                        max_instances INT,
                        expiry TIMESTAMP,
                        usage_count INT DEFAULT 0,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                ''')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS user_instances (
                        id SERIAL PRIMARY KEY,
                        key_id UUID,
                        user_id BIGINT,
                        port INT,
                        last_heartbeat TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                ''')
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_instances_user ON user_instances(user_id)
                ''')
        db_pool = None
    else:
        # SQLite (for development)
        import aiosqlite
        async def create_db_pool():
            db_path = DATABASE_URL.replace("sqlite:///", "")
            return await aiosqlite.connect(db_path)
        
        async def init_db(conn):
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS core_keys (
                    key_id TEXT PRIMARY KEY,
                    issued_to INTEGER,
                    issued_by INTEGER,
                    max_instances INTEGER,
                    expiry TIMESTAMP,
                    usage_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS user_instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT,
                    user_id INTEGER,
                    port INTEGER,
                    last_heartbeat TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            await conn.commit()
        db_pool = None

    # ---------- JWT Helpers ----------
    def generate_jwt_key(user_id: int, days: int, max_instances: int) -> str:
        key_id = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(days=days)
        payload = {
            "key_id": key_id,
            "sub": user_id,
            "exp": expiry.timestamp(),
            "max_instances": max_instances,
            "usage": 0
        }
        token = jwt.encode(payload, ADMIN_JWT_SECRET, algorithm="HS256")
        return token, key_id, expiry

    # ---------- Admin Bot Setup ----------
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(bot, storage=MemoryStorage())
    dp.middleware.setup(LoggingMiddleware())

    # ---------- Admin Auth Decorator ----------
    def admin_only(func):
        @wraps(func)
        async def wrapper(message: types.Message, *args, **kwargs):
            if message.from_user.id not in ADMIN_IDS:
                await message.reply("⛔ Unauthorized.")
                return
            return await func(message, *args, **kwargs)
        return wrapper

    # ---------- Commands ----------
    @dp.message_handler(commands=['start'])
    @admin_only
    async def cmd_start(message: types.Message):
        await message.answer(
            "🔐 *Admin Bot Active*\n\n"
            "Commands:\n"
            "• `/genkey <user_id> <days> <max_instances>` - Issue Core Key\n"
            "• `/listkeys` - Show recent keys\n"
            "• `/revoke <key_id>` - Revoke a key\n"
            "• `/stats` - Show usage statistics\n"
            "• `/cleanup` - Remove expired keys/inactive instances",
            parse_mode=ParseMode.MARKDOWN
        )

    @dp.message_handler(commands=['genkey'])
    @admin_only
    async def cmd_genkey(message: types.Message):
        args = message.get_args().split()
        if len(args) < 3:
            return await message.reply(
                "Usage: `/genkey <user_id> <days> <max_instances>`\n"
                "Example: `/genkey 123456789 30 3`",
                parse_mode=ParseMode.MARKDOWN
            )
        try:
            target_user = int(args[0])
            days = int(args[1])
            max_instances = int(args[2])
        except ValueError:
            return await message.reply("❌ Invalid numbers.")

        token, key_id, expiry = generate_jwt_key(target_user, days, max_instances)

        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                await conn.execute(
                    "INSERT INTO core_keys (key_id, issued_to, issued_by, max_instances, expiry) VALUES (?, ?, ?, ?, ?)",
                    (key_id, target_user, message.from_user.id, max_instances, expiry.isoformat())
                )
                await conn.commit()
            else:
                await conn.execute(
                    "INSERT INTO core_keys (key_id, issued_to, issued_by, max_instances, expiry) VALUES ($1, $2, $3, $4, $5)",
                    key_id, target_user, message.from_user.id, max_instances, expiry
                )

        text = (
            f"✅ **Core Key Generated**\n\n"
            f"`{token}`\n\n"
            f"👤 User: `{target_user}`\n"
            f"📅 Expires: {expiry.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🖥 Max instances: {max_instances}"
        )
        await message.reply(text, parse_mode=ParseMode.MARKDOWN)

    @dp.message_handler(commands=['listkeys'])
    @admin_only
    async def cmd_listkeys(message: types.Message):
        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                cursor = await conn.execute("SELECT * FROM core_keys ORDER BY created_at DESC LIMIT 20")
                rows = await cursor.fetchall()
            else:
                rows = await conn.fetch("SELECT * FROM core_keys ORDER BY created_at DESC LIMIT 20")
        
        if not rows:
            return await message.reply("No keys found.")
        
        text = "📋 **Recent Core Keys:**\n\n"
        for r in rows:
            if isinstance(r, dict) or hasattr(r, 'keys'):
                key_id = r['key_id']
                issued_to = r['issued_to']
                usage = r['usage_count']
                max_inst = r['max_instances']
                expiry = r['expiry']
            else:  # sqlite row
                key_id, issued_to, _, _, max_inst, usage, _, expiry = r
            text += f"🆔 `{key_id}`\n👤 User: {issued_to}  Used: {usage}/{max_inst}\n📅 Exp: {expiry}\n\n"
        
        await message.reply(text, parse_mode=ParseMode.MARKDOWN)

    @dp.message_handler(commands=['revoke'])
    @admin_only
    async def cmd_revoke(message: types.Message):
        args = message.get_args().split()
        if not args:
            return await message.reply("Usage: `/revoke <key_id>`", parse_mode=ParseMode.MARKDOWN)
        key_id = args[0]
        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                await conn.execute("DELETE FROM core_keys WHERE key_id = ?", (key_id,))
                await conn.execute("UPDATE user_instances SET is_active = 0 WHERE key_id = ?", (key_id,))
                await conn.commit()
            else:
                await conn.execute("DELETE FROM core_keys WHERE key_id = $1", key_id)
                await conn.execute("UPDATE user_instances SET is_active = FALSE WHERE key_id = $1", key_id)
        await message.reply(f"✅ Key `{key_id}` revoked and instances deactivated.", parse_mode=ParseMode.MARKDOWN)

    @dp.message_handler(commands=['stats'])
    @admin_only
    async def cmd_stats(message: types.Message):
        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                total_keys = await conn.execute_fetchall("SELECT COUNT(*) FROM core_keys")
                total_keys = total_keys[0][0]
                active_instances = await conn.execute_fetchall("SELECT COUNT(*) FROM user_instances WHERE is_active=1")
                active_instances = active_instances[0][0]
            else:
                total_keys = await conn.fetchval("SELECT COUNT(*) FROM core_keys")
                active_instances = await conn.fetchval("SELECT COUNT(*) FROM user_instances WHERE is_active=TRUE")
        
        text = (
            f"📊 **Admin Statistics**\n\n"
            f"🔑 Total keys issued: {total_keys}\n"
            f"🖥 Active instances: {active_instances}\n"
            f"👥 Admin IDs: {', '.join(map(str, ADMIN_IDS))}"
        )
        await message.reply(text, parse_mode=ParseMode.MARKDOWN)

    @dp.message_handler(commands=['cleanup'])
    @admin_only
    async def cmd_cleanup(message: types.Message):
        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                await conn.execute("DELETE FROM core_keys WHERE expiry < datetime('now')")
                # Deactivate instances without heartbeat > 5 minutes
                await conn.execute("UPDATE user_instances SET is_active=0 WHERE last_heartbeat < datetime('now', '-5 minutes')")
                await conn.commit()
            else:
                await conn.execute("DELETE FROM core_keys WHERE expiry < NOW()")
                await conn.execute("UPDATE user_instances SET is_active = FALSE WHERE last_heartbeat < NOW() - INTERVAL '5 minutes'")
        await message.reply("✅ Cleanup completed.")

    # ---------- REST API for User Bots ----------
    async def handle_validate(request):
        try:
            data = await request.json()
            token = data.get("core_key")
            user_id = data.get("user_id")
            port = data.get("port")
        except:
            return web.json_response({"valid": False, "reason": "bad request"}, status=400)

        try:
            payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=["HS256"])
            key_id = payload["key_id"]
            issued_to = payload["sub"]
            max_instances = payload["max_instances"]
            exp = datetime.fromtimestamp(payload["exp"])
        except jwt.ExpiredSignatureError:
            return web.json_response({"valid": False, "reason": "expired"}, status=401)
        except jwt.InvalidTokenError:
            return web.json_response({"valid": False, "reason": "invalid"}, status=401)

        if str(issued_to) != str(user_id):
            return web.json_response({"valid": False, "reason": "user mismatch"}, status=401)

        async with db_pool.acquire() as conn:
            # Check key existence and usage
            if isinstance(conn, aiosqlite.Connection):
                row = await conn.execute_fetchone("SELECT * FROM core_keys WHERE key_id = ?", (key_id,))
            else:
                row = await conn.fetchrow("SELECT * FROM core_keys WHERE key_id = $1", key_id)
            
            if not row:
                return web.json_response({"valid": False, "reason": "key not found"}, status=401)
            
            usage_count = row['usage_count'] if isinstance(row, dict) or hasattr(row, 'keys') else row[5]
            if usage_count >= max_instances:
                return web.json_response({"valid": False, "reason": "max instances reached"}, status=401)
            
            # Check if this user already used this port (prevent reuse)
            if isinstance(conn, aiosqlite.Connection):
                used = await conn.execute_fetchone(
                    "SELECT EXISTS(SELECT 1 FROM user_instances WHERE user_id=? AND port=?)",
                    (user_id, port)
                )
                used = used[0] if used else 0
            else:
                used = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM user_instances WHERE user_id=$1 AND port=$2)",
                    user_id, port
                )
            if used:
                return web.json_response({"valid": False, "reason": "port already used by you"}, status=401)
            
            # Register instance
            if isinstance(conn, aiosqlite.Connection):
                await conn.execute(
                    "INSERT INTO user_instances (key_id, user_id, port, last_heartbeat) VALUES (?, ?, ?, datetime('now'))",
                    (key_id, user_id, port)
                )
                await conn.execute(
                    "UPDATE core_keys SET usage_count = usage_count + 1 WHERE key_id = ?",
                    (key_id,)
                )
                await conn.commit()
            else:
                await conn.execute(
                    "INSERT INTO user_instances (key_id, user_id, port, last_heartbeat) VALUES ($1, $2, $3, NOW())",
                    key_id, int(user_id), port
                )
                await conn.execute(
                    "UPDATE core_keys SET usage_count = usage_count + 1 WHERE key_id = $1",
                    key_id
                )
        
        return web.json_response({"valid": True, "expires": exp.timestamp()})

    async def handle_heartbeat(request):
        try:
            data = await request.json()
            user_id = data.get("user_id")
            port = data.get("port")
        except:
            return web.json_response({"status": "error"}, status=400)

        async with db_pool.acquire() as conn:
            if isinstance(conn, aiosqlite.Connection):
                await conn.execute(
                    "UPDATE user_instances SET last_heartbeat = datetime('now') WHERE user_id=? AND port=?",
                    (user_id, port)
                )
                await conn.commit()
            else:
                await conn.execute(
                    "UPDATE user_instances SET last_heartbeat = NOW() WHERE user_id=$1 AND port=$2",
                    user_id, port
                )
        return web.json_response({"status": "ok"})

    # ---------- Web Application for API ----------
    web_app = web.Application()
    web_app.router.add_post("/api/validate", handle_validate)
    web_app.router.add_post("/api/heartbeat", handle_heartbeat)

    # ---------- Startup & Shutdown ----------
    async def on_startup(dp):
        global db_pool
        db_pool = await create_db_pool()
        if isinstance(db_pool, aiosqlite.Connection):
            await init_db(db_pool)
        else:
            await init_db(db_pool)
        
        # Start aiohttp server
        runner = web.AppRunner(web_app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', PORT)
        await site.start()
        logger.info(f"Admin API running on port {PORT}")

        # Set webhook
        if WEBHOOK_URL:
            await bot.set_webhook(WEBHOOK_URL + WEBHOOK_PATH)
            logger.info(f"Webhook set to {WEBHOOK_URL}{WEBHOOK_PATH}")

    async def on_shutdown(dp):
        await bot.delete_webhook()
        await dp.storage.close()
        await dp.storage.wait_closed()
        if db_pool:
            await db_pool.close()

    if __name__ == "__main__":
        WEBHOOK_PATH = "/webhook"
        executor.start_webhook(
            dispatcher=dp,
            webhook_path=WEBHOOK_PATH,
            on_startup=on_startup,
            on_shutdown=on_shutdown,
            skip_updates=True,
            host="0.0.0.0",
            port=PORT,
        )

# -------------------- MODE: USER BOT --------------------
elif BOT_MODE == "user":
    logger.info("Starting in USER mode")

    # ---------- Core Key Validation (with fallback local decode) ----------
    def validate_core_key():
        if not CORE_KEY:
            logger.error("CORE_KEY not set in .env")
            return False
        
        # First, try to validate via Admin API if available
        if ADMIN_API_URL:
            try:
                resp = requests.post(f"{ADMIN_API_URL.rstrip('/')}/api/validate", json={
                    "core_key": CORE_KEY,
                    "user_id": USER_ID,
                    "port": PORT
                }, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    logger.info("✅ Core Key validated by Admin API")
                    return True
                else:
                    reason = resp.json().get("reason", "unknown")
                    logger.error(f"❌ Admin API validation failed: {reason}")
                    # fall through to local validation
            except Exception as e:
                logger.warning(f"Admin API unreachable: {e}, falling back to local validation")
        
        # Fallback: local JWT decode (signature not verified if secret unknown)
        try:
            payload = jwt.decode(CORE_KEY, options={"verify_signature": False})
            exp = payload.get("exp")
            sub = payload.get("sub")
            if exp and time.time() < exp:
                if str(sub) == str(USER_ID):
                    logger.info("✅ Core Key locally valid (signature not verified)")
                    return True
                else:
                    logger.error("❌ Core Key user mismatch")
            else:
                logger.error("❌ Core Key expired")
        except Exception as e:
            logger.error(f"❌ Invalid Core Key: {e}")
        
        return False

    if not validate_core_key():
        logger.critical("Core Key validation failed. Exiting.")
        sys.exit(1)

    # ---------- Per-User Database & Port Uniqueness ----------
    DB_PATH = f"user_{USER_ID}_data.db"
    
    def init_user_db():
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Ports used by this user (prevent reuse)
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_ports (
                port INTEGER PRIMARY KEY,
                first_used TIMESTAMP
            )
        ''')
        
        # Polls
        c.execute('''
            CREATE TABLE IF NOT EXISTS polls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                is_anonymous BOOLEAN DEFAULT 0,
                is_closed BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER
            )
        ''')
        
        # Options
        c.execute('''
            CREATE TABLE IF NOT EXISTS options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id INTEGER,
                text TEXT,
                FOREIGN KEY(poll_id) REFERENCES polls(id) ON DELETE CASCADE
            )
        ''')
        
        # Votes
        c.execute('''
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id INTEGER,
                option_id INTEGER,
                user_id INTEGER,
                voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(poll_id) REFERENCES polls(id),
                FOREIGN KEY(option_id) REFERENCES options(id)
            )
        ''')
        
        # User activity (track last seen, current state)
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                user_id INTEGER PRIMARY KEY,
                last_seen TIMESTAMP,
                current_poll_id INTEGER,
                last_bot_message_id INTEGER
            )
        ''')
        
        # Team access (other users allowed to manage polls)
        c.execute('''
            CREATE TABLE IF NOT EXISTS team (
                user_id INTEGER PRIMARY KEY,
                added_by INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        return conn

    # Initialize DB
    user_db_conn = init_user_db()
    
    def get_db_connection():
        # Return a new connection for thread safety
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------- Port Uniqueness Enforcement ----------
    if is_port_in_use(PORT):
        logger.error(f"Port {PORT} is already in use by another process on this machine.")
        sys.exit(1)
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT port FROM user_ports WHERE port=?", (PORT,))
    if c.fetchone():
        logger.error(f"You have already used port {PORT} before. You cannot reuse the same port.")
        conn.close()
        sys.exit(1)
    c.execute("INSERT INTO user_ports (port, first_used) VALUES (?, ?)", (PORT, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    logger.info(f"Registered port {PORT} for this user")

    # ---------- Heartbeat to Admin Bot ----------
    def heartbeat_worker():
        while True:
            if ADMIN_API_URL:
                try:
                    requests.post(f"{ADMIN_API_URL.rstrip('/')}/api/heartbeat", json={
                        "user_id": USER_ID,
                        "port": PORT
                    }, timeout=5)
                    logger.debug("Heartbeat sent")
                except:
                    pass
            time.sleep(60)  # every minute
    threading.Thread(target=heartbeat_worker, daemon=True).start()

    # ---------- Telegram Bot Setup ----------
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(bot, storage=MemoryStorage())
    dp.middleware.setup(LoggingMiddleware())

    # ---------- FSM States for Poll Creation ----------
    class PollCreation(StatesGroup):
        waiting_question = State()
        waiting_options = State()
        waiting_edit_question = State()
        waiting_add_option = State()

    # ---------- Helper Functions ----------
    async def update_or_send_message(chat_id, text, reply_markup=None, parse_mode=None):
        """Single-message editing: delete previous bot message and send new one."""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT last_bot_message_id FROM user_activity WHERE user_id=?", (chat_id,))
        row = c.fetchone()
        last_msg_id = row['last_bot_message_id'] if row else None
        conn.close()
        
        if last_msg_id:
            try:
                await bot.delete_message(chat_id, last_msg_id)
            except:
                pass
        sent = await bot.send_message(chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO user_activity (user_id, last_seen, last_bot_message_id) VALUES (?, ?, ?)",
                  (chat_id, datetime.utcnow().isoformat(), sent.message_id))
        conn.commit()
        conn.close()
        return sent

    def main_menu_keyboard():
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("📊 Create Poll", callback_data="menu_create"),
            InlineKeyboardButton("👁 View Live Poll", callback_data="menu_view_live"),
            InlineKeyboardButton("📈 Show Results", callback_data="menu_results"),
            InlineKeyboardButton("⚙️ Manage Polls", callback_data="menu_manage"),
            InlineKeyboardButton("👥 Team Access", callback_data="menu_team"),
            InlineKeyboardButton("🛠 Settings", callback_data="menu_settings"),
            InlineKeyboardButton("📤 Export Data", callback_data="menu_export")
        )
        return kb

    def poll_options_keyboard(poll_id):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, text FROM options WHERE poll_id=?", (poll_id,))
        options = c.fetchall()
        conn.close()
        
        kb = InlineKeyboardMarkup(row_width=1)
        for opt in options:
            kb.add(InlineKeyboardButton(opt["text"], callback_data=f"vote_{poll_id}_{opt['id']}"))
        kb.add(InlineKeyboardButton("🔙 Back", callback_data="back_main"))
        return kb

    def manage_polls_keyboard():
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, question, is_closed FROM polls ORDER BY created_at DESC LIMIT 10")
        polls = c.fetchall()
        conn.close()
        
        kb = InlineKeyboardMarkup(row_width=1)
        for p in polls:
            status = "🔒" if p['is_closed'] else "📢"
            kb.add(InlineKeyboardButton(f"{status} {p['question'][:30]}", callback_data=f"manage_{p['id']}"))
        kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
        return kb

    def is_owner_or_team(user_id: int) -> bool:
        if user_id == USER_ID:
            return True
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT user_id FROM team WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        return row is not None

    # ---------- Authorization Decorator for User Bot ----------
    def authorized_only(func):
        @wraps(func)
        async def wrapper(message: types.Message, *args, **kwargs):
            if not is_owner_or_team(message.from_user.id):
                await message.reply("⛔ You are not authorized to use this bot.")
                return
            return await func(message, *args, **kwargs)
        return wrapper

    def authorized_callback(func):
        @wraps(func)
        async def wrapper(callback: CallbackQuery, *args, **kwargs):
            if not is_owner_or_team(callback.from_user.id):
                await callback.answer("⛔ Unauthorized", show_alert=True)
                return
            return await func(callback, *args, **kwargs)
        return wrapper

    # ---------- Command Handlers ----------
    @dp.message_handler(commands=['start'])
    @authorized_only
    async def cmd_start(message: types.Message):
        await update_or_send_message(
            message.chat.id,
            "🗳 *Advanced Voting Bot*\n\nWelcome! Choose an option:",
            reply_markup=main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )

    # ---------- Menu Callbacks ----------
    @dp.callback_query_handler(lambda c: c.data == "back_main")
    @authorized_callback
    async def back_to_main(callback: CallbackQuery):
        await update_or_send_message(
            callback.message.chat.id,
            "🗳 *Main Menu*",
            reply_markup=main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data.startswith("menu_"))
    @authorized_callback
    async def process_menu(callback: CallbackQuery):
        action = callback.data.split("_")[1]
        
        if action == "create":
            await PollCreation.waiting_question.set()
            await update_or_send_message(
                callback.message.chat.id,
                "📝 *Create a New Poll*\n\nSend me the poll question:",
                reply_markup=create_backup_keyboard(),
                parse_mode=ParseMode.MARKDOWN
            )
            await callback.answer()
        
        elif action == "view_live":
            url = f"http://127.0.0.1:{PORT}"
            await update_or_send_message(
                callback.message.chat.id,
                f"🌍 *Live Poll Dashboard*\n\nOpen this link in your browser:\n`{url}`\n\n"
                "Real-time updates every 3 seconds (AJAX).",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("🔄 Open Browser", url=url),
                    InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
                )
            )
            await callback.answer()
        
        elif action == "results":
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM polls WHERE is_closed=0 ORDER BY created_at DESC LIMIT 5")
            polls = c.fetchall()
            conn.close()
            
            if not polls:
                await update_or_send_message(
                    callback.message.chat.id,
                    "📊 No active polls.",
                    reply_markup=main_menu_keyboard()
                )
            else:
                text = "📊 *Live Results*\n\n"
                for p in polls:
                    text += f"*{p['question']}*\n"
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute("""
                        SELECT o.text, COUNT(v.id) as votes 
                        FROM options o LEFT JOIN votes v ON o.id = v.option_id 
                        WHERE o.poll_id=? GROUP BY o.id
                    """, (p['id'],))
                    for opt in c.fetchall():
                        text += f"‣ {opt['text']}: {opt['votes']} votes\n"
                    conn.close()
                    text += "\n"
                await update_or_send_message(
                    callback.message.chat.id,
                    text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_menu_keyboard()
                )
            await callback.answer()
        
        elif action == "manage":
            kb = manage_polls_keyboard()
            await update_or_send_message(
                callback.message.chat.id,
                "⚙️ *Manage Polls*\nSelect a poll to edit/close/delete:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=kb
            )
            await callback.answer()
        
        elif action == "team":
            # Show team management
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT user_id, added_at FROM team ORDER BY added_at DESC")
            members = c.fetchall()
            conn.close()
            
            text = "👥 *Team Access*\n\n"
            text += f"👑 Owner: `{USER_ID}`\n\n"
            if members:
                text += "**Members:**\n"
                for m in members:
                    text += f"• `{m['user_id']}` (added {m['added_at'][:10]})\n"
            else:
                text += "No team members added yet.\n"
            text += "\nUse the buttons below to manage."
            
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(
                InlineKeyboardButton("➕ Add User", callback_data="team_add"),
                InlineKeyboardButton("❌ Remove User", callback_data="team_remove")
            )
            kb.add(InlineKeyboardButton("🔙 Main Menu", callback_data="back_main"))
            
            await update_or_send_message(
                callback.message.chat.id,
                text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=kb
            )
            await callback.answer()
        
        elif action == "settings":
            text = (
                f"🛠 *Settings*\n\n"
                f"**Your User ID:** `{USER_ID}`\n"
                f"**Port:** `{PORT}`\n"
                f"**Core Key:** `{CORE_KEY[:15]}...{CORE_KEY[-15:]}`\n"
                f"**Database:** `{DB_PATH}`\n\n"
                f"⚙️ Options:"
            )
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(
                InlineKeyboardButton("🔁 Change Port", callback_data="settings_change_port"),
                InlineKeyboardButton("📥 Export DB", callback_data="settings_export_db"),
                InlineKeyboardButton("🔄 Restart Bot", callback_data="settings_restart"),
                InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
            )
            await update_or_send_message(
                callback.message.chat.id,
                text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=kb
            )
            await callback.answer()
        
        elif action == "export":
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(
                InlineKeyboardButton("📊 Export Polls (CSV)", callback_data="export_polls_csv"),
                InlineKeyboardButton("📈 Export Polls (JSON)", callback_data="export_polls_json"),
                InlineKeyboardButton("🗂 Export All Data", callback_data="export_all"),
                InlineKeyboardButton("🔙 Main Menu", callback_data="back_main")
            )
            await update_or_send_message(
                callback.message.chat.id,
                "📤 *Export Data*\nChoose format:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=kb
            )
            await callback.answer()

    # ---------- Poll Creation Flow ----------
    @dp.message_handler(state=PollCreation.waiting_question)
    @authorized_only
    async def poll_question(message: types.Message, state: FSMContext):
        question = message.text.strip()
        if not question:
            await message.reply("❌ Question cannot be empty.")
            return
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO polls (question, created_by) VALUES (?, ?)", (question, message.from_user.id))
        poll_id = c.lastrowid
        conn.commit()
        conn.close()
        
        await state.update_data(poll_id=poll_id)
        await PollCreation.waiting_options.set()
        
        await message.reply(
            "✍️ Send the poll options, one per line.\n"
            "Example:\n"
            "`Option 1`\n"
            "`Option 2`\n"
            "`Option 3`",
            parse_mode=ParseMode.MARKDOWN
        )

    @dp.message_handler(state=PollCreation.waiting_options)
    @authorized_only
    async def poll_options(message: types.Message, state: FSMContext):
        options_text = message.text.strip()
        options = [opt.strip() for opt in options_text.split('\n') if opt.strip()]
        
        if len(options) < 2:
            await message.reply("❌ At least 2 options are required.")
            return
        
        data = await state.get_data()
        poll_id = data['poll_id']
        
        conn = get_db_connection()
        c = conn.cursor()
        for opt in options:
            c.execute("INSERT INTO options (poll_id, text) VALUES (?, ?)", (poll_id, opt))
        conn.commit()
        conn.close()
        
        await state.finish()
        await update_or_send_message(
            message.chat.id,
            f"✅ Poll created!\n\n**Question:** {options_text.split(chr(10))[0]}...",
            reply_markup=main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )

    # ---------- Voting ----------
    @dp.callback_query_handler(lambda c: c.data.startswith("vote_"))
    @authorized_callback
    async def vote_callback(callback: CallbackQuery):
        _, poll_id, option_id = callback.data.split("_")
        poll_id = int(poll_id)
        option_id = int(option_id)
        user_id = callback.from_user.id
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Check if poll is anonymous
        c.execute("SELECT is_anonymous, is_closed FROM polls WHERE id=?", (poll_id,))
        poll = c.fetchone()
        if not poll:
            await callback.answer("❌ Poll not found.", show_alert=True)
            conn.close()
            return
        if poll['is_closed']:
            await callback.answer("🔒 This poll is closed.", show_alert=True)
            conn.close()
            return
        
        if not poll['is_anonymous']:
            # Remove previous vote from this user
            c.execute("DELETE FROM votes WHERE poll_id=? AND user_id=?", (poll_id, user_id))
        
        # Insert new vote
        c.execute("INSERT INTO votes (poll_id, option_id, user_id) VALUES (?, ?, ?)", (poll_id, option_id, user_id))
        conn.commit()
        conn.close()
        
        await callback.answer("✅ Vote recorded!")
        
        # Optionally, show live activity
        await bot.send_message(
            callback.message.chat.id,
            f"🗳 User `{user_id}` voted in poll #{poll_id}",
            disable_notification=True
        )

    # ---------- Manage Polls ----------
    @dp.callback_query_handler(lambda c: c.data.startswith("manage_"))
    @authorized_callback
    async def manage_poll(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[1])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM polls WHERE id=?", (poll_id,))
        poll = c.fetchone()
        conn.close()
        
        if not poll:
            await callback.answer("Poll not found.", show_alert=True)
            return
        
        text = f"⚙️ *Manage Poll*\n\n**ID:** {poll_id}\n**Question:** {poll['question']}\n**Anonymous:** {'Yes' if poll['is_anonymous'] else 'No'}\n**Closed:** {'Yes' if poll['is_closed'] else 'No'}"
        
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("📝 Edit Question", callback_data=f"edit_q_{poll_id}"),
            InlineKeyboardButton("➕ Add Option", callback_data=f"add_opt_{poll_id}"),
            InlineKeyboardButton("❌ Delete Option", callback_data=f"del_opt_{poll_id}"),
            InlineKeyboardButton("🔒 Toggle Close", callback_data=f"toggle_close_{poll_id}"),
            InlineKeyboardButton("🔄 Toggle Anonymous", callback_data=f"toggle_anon_{poll_id}"),
            InlineKeyboardButton("🗑 Delete Poll", callback_data=f"delete_poll_{poll_id}"),
            InlineKeyboardButton("📊 Export Results", callback_data=f"export_poll_{poll_id}")
        )
        kb.add(InlineKeyboardButton("🔙 Back to Manage", callback_data="menu_manage"))
        
        await update_or_send_message(
            callback.message.chat.id,
            text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=kb
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data.startswith("edit_q_"))
    @authorized_callback
    async def edit_question(callback: CallbackQuery, state: FSMContext):
        poll_id = int(callback.data.split("_")[2])
        await state.update_data(poll_id=poll_id)
        await PollCreation.waiting_edit_question.set()
        await update_or_send_message(
            callback.message.chat.id,
            "✏️ Send the new question:",
            reply_markup=create_backup_keyboard()
        )
        await callback.answer()

    @dp.message_handler(state=PollCreation.waiting_edit_question)
    @authorized_only
    async def save_edited_question(message: types.Message, state: FSMContext):
        data = await state.get_data()
        poll_id = data['poll_id']
        new_question = message.text.strip()
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE polls SET question=? WHERE id=?", (new_question, poll_id))
        conn.commit()
        conn.close()
        
        await state.finish()
        await update_or_send_message(
            message.chat.id,
            "✅ Question updated.",
            reply_markup=main_menu_keyboard()
        )

    @dp.callback_query_handler(lambda c: c.data.startswith("add_opt_"))
    @authorized_callback
    async def add_option_start(callback: CallbackQuery, state: FSMContext):
        poll_id = int(callback.data.split("_")[2])
        await state.update_data(poll_id=poll_id)
        await PollCreation.waiting_add_option.set()
        await update_or_send_message(
            callback.message.chat.id,
            "➕ Send the new option text:",
            reply_markup=create_backup_keyboard()
        )
        await callback.answer()

    @dp.message_handler(state=PollCreation.waiting_add_option)
    @authorized_only
    async def save_new_option(message: types.Message, state: FSMContext):
        data = await state.get_data()
        poll_id = data['poll_id']
        opt_text = message.text.strip()
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO options (poll_id, text) VALUES (?, ?)", (poll_id, opt_text))
        conn.commit()
        conn.close()
        
        await state.finish()
        await update_or_send_message(
            message.chat.id,
            "✅ Option added.",
            reply_markup=main_menu_keyboard()
        )

    @dp.callback_query_handler(lambda c: c.data.startswith("del_opt_"))
    @authorized_callback
    async def delete_option_menu(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, text FROM options WHERE poll_id=?", (poll_id,))
        options = c.fetchall()
        conn.close()
        
        if not options:
            await callback.answer("No options to delete.", show_alert=True)
            return
        
        kb = InlineKeyboardMarkup(row_width=1)
        for opt in options:
            kb.add(InlineKeyboardButton(f"❌ {opt['text']}", callback_data=f"remove_opt_{opt['id']}"))
        kb.add(InlineKeyboardButton("🔙 Back", callback_data=f"manage_{poll_id}"))
        
        await update_or_send_message(
            callback.message.chat.id,
            "Select an option to delete:",
            reply_markup=kb
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data.startswith("remove_opt_"))
    @authorized_callback
    async def remove_option(callback: CallbackQuery):
        opt_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM options WHERE id=?", (opt_id,))
        c.execute("DELETE FROM votes WHERE option_id=?", (opt_id,))
        conn.commit()
        conn.close()
        
        await callback.answer("✅ Option deleted.", show_alert=True)
        # Refresh manage page
        await manage_poll(callback)

    @dp.callback_query_handler(lambda c: c.data.startswith("toggle_close_"))
    @authorized_callback
    async def toggle_close(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT is_closed FROM polls WHERE id=?", (poll_id,))
        is_closed = c.fetchone()['is_closed']
        new_state = 0 if is_closed else 1
        c.execute("UPDATE polls SET is_closed=? WHERE id=?", (new_state, poll_id))
        conn.commit()
        conn.close()
        
        await callback.answer(f"Poll {'closed' if new_state else 'opened'}.", show_alert=True)
        await manage_poll(callback)

    @dp.callback_query_handler(lambda c: c.data.startswith("toggle_anon_"))
    @authorized_callback
    async def toggle_anonymous(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT is_anonymous FROM polls WHERE id=?", (poll_id,))
        is_anon = c.fetchone()['is_anonymous']
        new_state = 0 if is_anon else 1
        c.execute("UPDATE polls SET is_anonymous=? WHERE id=?", (new_state, poll_id))
        conn.commit()
        conn.close()
        
        await callback.answer(f"Anonymous voting {'enabled' if new_state else 'disabled'}.", show_alert=True)
        await manage_poll(callback)

    @dp.callback_query_handler(lambda c: c.data.startswith("delete_poll_"))
    @authorized_callback
    async def delete_poll(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM votes WHERE poll_id=?", (poll_id,))
        c.execute("DELETE FROM options WHERE poll_id=?", (poll_id,))
        c.execute("DELETE FROM polls WHERE id=?", (poll_id,))
        conn.commit()
        conn.close()
        
        await callback.answer("🗑 Poll deleted.", show_alert=True)
        await back_to_main(callback)

    @dp.callback_query_handler(lambda c: c.data.startswith("export_poll_"))
    @authorized_callback
    async def export_poll_results(callback: CallbackQuery):
        poll_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT question FROM polls WHERE id=?", (poll_id,))
        poll = c.fetchone()
        if not poll:
            await callback.answer("Poll not found.", show_alert=True)
            return
        
        c.execute("""
            SELECT o.text, COUNT(v.id) as votes, GROUP_CONCAT(v.user_id) as voters
            FROM options o
            LEFT JOIN votes v ON o.id = v.option_id
            WHERE o.poll_id=?
            GROUP BY o.id
        """, (poll_id,))
        results = c.fetchall()
        conn.close()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Option", "Votes", "Voters (User IDs)"])
        for row in results:
            writer.writerow([row['text'], row['votes'], row['voters'] or ''])
        
        csv_data = output.getvalue().encode('utf-8')
        
        await callback.message.answer_document(
            types.InputFile(io.BytesIO(csv_data), filename=f"poll_{poll_id}_results.csv"),
            caption=f"📊 Results for: {poll['question']}"
        )
        await callback.answer()

    # ---------- Team Management ----------
    @dp.callback_query_handler(lambda c: c.data == "team_add")
    @authorized_callback
    async def team_add_prompt(callback: CallbackQuery, state: FSMContext):
        await state.set_state("team_add")
        await update_or_send_message(
            callback.message.chat.id,
            "👤 Send the Telegram User ID to add as a team member:",
            reply_markup=create_backup_keyboard()
        )
        await callback.answer()

    @dp.message_handler(state="team_add")
    @authorized_only
    async def team_add_execute(message: types.Message, state: FSMContext):
        try:
            new_user = int(message.text.strip())
        except ValueError:
            await message.reply("❌ Invalid User ID. Must be a number.")
            return
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO team (user_id, added_by) VALUES (?, ?)", (new_user, message.from_user.id))
        conn.commit()
        conn.close()
        
        await state.finish()
        await update_or_send_message(
            message.chat.id,
            f"✅ User `{new_user}` added to team.",
            reply_markup=main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )

    @dp.callback_query_handler(lambda c: c.data == "team_remove")
    @authorized_callback
    async def team_remove_prompt(callback: CallbackQuery):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT user_id FROM team")
        members = c.fetchall()
        conn.close()
        
        if not members:
            await callback.answer("No team members to remove.", show_alert=True)
            return
        
        kb = InlineKeyboardMarkup(row_width=1)
        for m in members:
            kb.add(InlineKeyboardButton(f"❌ {m['user_id']}", callback_data=f"team_remove_{m['user_id']}"))
        kb.add(InlineKeyboardButton("🔙 Back", callback_data="menu_team"))
        
        await update_or_send_message(
            callback.message.chat.id,
            "Select a user to remove from team:",
            reply_markup=kb
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data.startswith("team_remove_"))
    @authorized_callback
    async def team_remove_execute(callback: CallbackQuery):
        user_id = int(callback.data.split("_")[2])
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM team WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        
        await callback.answer(f"User {user_id} removed.", show_alert=True)
        await process_menu(callback)  # refresh team menu

    # ---------- Settings ----------
    @dp.callback_query_handler(lambda c: c.data == "settings_change_port")
    @authorized_callback
    async def settings_change_port(callback: CallbackQuery):
        await update_or_send_message(
            callback.message.chat.id,
            "⚠️ *Change Port*\n\n"
            "To change the port, edit your `.env` file, set `PORT=NEW_PORT`, and restart the bot.\n\n"
            "**Note:** You cannot reuse a port you've used before.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=create_backup_keyboard()
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data == "settings_export_db")
    @authorized_callback
    async def settings_export_db(callback: CallbackQuery):
        # Send the SQLite database file
        try:
            with open(DB_PATH, 'rb') as f:
                await callback.message.answer_document(
                    types.InputFile(io.BytesIO(f.read()), filename=DB_PATH),
                    caption="📦 Full database export."
                )
        except Exception as e:
            await callback.answer(f"Error: {e}", show_alert=True)
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data == "settings_restart")
    @authorized_callback
    async def settings_restart(callback: CallbackQuery):
        await callback.answer("🔄 Restarting bot...", show_alert=True)
        # Graceful shutdown and restart
        os.execl(sys.executable, sys.executable, *sys.argv)

    # ---------- Export Menu ----------
    @dp.callback_query_handler(lambda c: c.data == "export_polls_csv")
    @authorized_callback
    async def export_polls_csv(callback: CallbackQuery):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT p.id, p.question, p.is_anonymous, p.is_closed, p.created_at,
                   o.text as option_text, COUNT(v.id) as votes
            FROM polls p
            LEFT JOIN options o ON p.id = o.poll_id
            LEFT JOIN votes v ON o.id = v.option_id
            GROUP BY p.id, o.id
            ORDER BY p.created_at DESC
        """)
        rows = c.fetchall()
        conn.close()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Poll ID", "Question", "Anonymous", "Closed", "Created", "Option", "Votes"])
        for row in rows:
            writer.writerow(row)
        
        csv_data = output.getvalue().encode('utf-8')
        await callback.message.answer_document(
            types.InputFile(io.BytesIO(csv_data), filename="polls_export.csv"),
            caption="📊 Polls export (CSV)"
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data == "export_polls_json")
    @authorized_callback
    async def export_polls_json(callback: CallbackQuery):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM polls")
        polls = c.fetchall()
        data = []
        for p in polls:
            c.execute("SELECT * FROM options WHERE poll_id=?", (p['id'],))
            options = c.fetchall()
            opts = []
            for o in options:
                c.execute("SELECT user_id FROM votes WHERE option_id=?", (o['id'],))
                voters = [v['user_id'] for v in c.fetchall()]
                opts.append({
                    "id": o['id'],
                    "text": o['text'],
                    "votes": len(voters),
                    "voters": voters if not p['is_anonymous'] else []
                })
            data.append({
                "id": p['id'],
                "question": p['question'],
                "is_anonymous": bool(p['is_anonymous']),
                "is_closed": bool(p['is_closed']),
                "created_at": p['created_at'],
                "options": opts
            })
        conn.close()
        
        json_data = json.dumps(data, indent=2, default=str).encode('utf-8')
        await callback.message.answer_document(
            types.InputFile(io.BytesIO(json_data), filename="polls_export.json"),
            caption="📊 Polls export (JSON)"
        )
        await callback.answer()

    @dp.callback_query_handler(lambda c: c.data == "export_all")
    @authorized_callback
    async def export_all(callback: CallbackQuery):
        # Export full database as .db file
        await settings_export_db(callback)

    # ---------- Flask Server for Live Dashboard ----------
    flask_app = Flask(__name__)

    @flask_app.route('/')
    def home():
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Live Voting Dashboard</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial; padding: 20px; background: #f5f5f5; }
                .poll { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .option { margin: 10px 0; padding: 10px; border-bottom: 1px solid #eee; }
                .votes { color: #2ecc71; font-weight: bold; }
                .bar { background: #3498db; height: 20px; border-radius: 10px; transition: width 0.3s; }
                .user-activity { background: #fff; padding: 10px; border-radius: 5px; margin-top: 20px; }
            </style>
            <script>
                async function fetchPolls() {
                    const res = await fetch('/api/polls');
                    const polls = await res.json();
                    const container = document.getElementById('polls');
                    container.innerHTML = '';
                    polls.forEach(poll => {
                        const div = document.createElement('div');
                        div.className = 'poll';
                        let html = `<h3>${poll.question}</h3>`;
                        let totalVotes = poll.options.reduce((acc, o) => acc + o.votes, 0);
                        poll.options.forEach(opt => {
                            let percent = totalVotes ? (opt.votes / totalVotes * 100).toFixed(1) : 0;
                            html += `
                                <div class="option">
                                    <strong>${opt.text}</strong> 
                                    <span class="votes">${opt.votes} votes (${percent}%)</span>
                                    <div class="bar" style="width: ${percent}%;"></div>
                                </div>
                            `;
                        });
                        html += `<p><small>Poll ID: ${poll.id} | Anonymous: ${poll.is_anonymous ? 'Yes' : 'No'} | Closed: ${poll.is_closed ? 'Yes' : 'No'}</small></p>`;
                        div.innerHTML = html;
                        container.appendChild(div);
                    });
                }
                async function fetchActivity() {
                    const res = await fetch('/api/activity');
                    const activity = await res.json();
                    const activityDiv = document.getElementById('activity');
                    if (activity.length) {
                        let html = '<h4>👥 Active Users</h4><ul>';
                        activity.forEach(u => {
                            html += `<li>User ${u.user_id} on poll #${u.poll_id} (${u.last_seen})</li>`;
                        });
                        html += '</ul>';
                        activityDiv.innerHTML = html;
                    } else {
                        activityDiv.innerHTML = '<p>No active users.</p>';
                    }
                }
                setInterval(() => {
                    fetchPolls();
                    fetchActivity();
                }, 3000);
                window.onload = () => {
                    fetchPolls();
                    fetchActivity();
                };
            </script>
        </head>
        <body>
            <h1>🗳 Live Poll Dashboard</h1>
            <div id="activity" class="user-activity"></div>
            <div id="polls"></div>
        </body>
        </html>
        ''')

    @flask_app.route('/api/polls')
    def api_polls():
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, question, is_anonymous, is_closed FROM polls ORDER BY created_at DESC")
        polls = c.fetchall()
        result = []
        for p in polls:
            c.execute("""
                SELECT o.id, o.text, COUNT(v.id) as votes 
                FROM options o 
                LEFT JOIN votes v ON o.id = v.option_id 
                WHERE o.poll_id=? 
                GROUP BY o.id
            """, (p['id'],))
            options = [{"id": row["id"], "text": row["text"], "votes": row["votes"]} for row in c.fetchall()]
            result.append({
                "id": p["id"],
                "question": p["question"],
                "is_anonymous": bool(p["is_anonymous"]),
                "is_closed": bool(p["is_closed"]),
                "options": options
            })
        conn.close()
        return jsonify(result)

    @flask_app.route('/api/activity')
    def api_activity():
        conn = get_db_connection()
        c = conn.cursor()
        # Show users who voted in the last 10 minutes
        c.execute("""
            SELECT DISTINCT user_id, poll_id, MAX(voted_at) as last_vote
            FROM votes
            WHERE voted_at > datetime('now', '-10 minutes')
            GROUP BY user_id
            ORDER BY last_vote DESC
            LIMIT 20
        """)
        activity = [{"user_id": row["user_id"], "poll_id": row["poll_id"], "last_seen": row["last_vote"]} for row in c.fetchall()]
        conn.close()
        return jsonify(activity)

    def run_flask():
        flask_app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

    # Start Flask in a background thread
    threading.Thread(target=run_flask, daemon=True).start()
    logger.info(f"Flask live dashboard running on http://127.0.0.1:{PORT}")

    # ---------- Start Bot Polling ----------
    if __name__ == "__main__":
        logger.info("Starting user bot with polling...")
        executor.start_polling(dp, skip_updates=True)

else:
    logger.error("Invalid BOT_MODE. Set to 'admin' or 'user' in .env")
    sys.exit(1)
