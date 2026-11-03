#!/usr/bin/env python3
"""
ZIAD HOST - نظام استضافة متطور مع لوحة تحكم وإدارة وبوت تيليجرام مدمج
طُوِّر بواسطة: 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜 | @Y_20_20
"""

import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import threading
import requests
import shutil
import zipfile
import signal
import logging
import base64
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, make_response

# مكتبات التشفير للحماية المتقدمة
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# مكتبات تيليجرام
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)

# إعدادات التسجيل (Logging)
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

# مسارات التخزين الإضافية المطلوبة بنظام الحماية والهيكلة
RUNNING_DIR = os.path.join(BASE_DIR, "active_bots")
LOGS_DIR = os.path.join(BASE_DIR, "bot_logs")
DB_DIR = os.path.join(BASE_DIR, "database")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
STORE_DIR = os.path.join(BASE_DIR, "store_files")
THUMBS_DIR = os.path.join(ASSETS_DIR, "thumbs")
MARKET_DIR = os.path.join(BASE_DIR, "market")
ENV_DIR = os.path.join(BASE_DIR, "bot_environments")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted_files")

for d in [RUNNING_DIR, LOGS_DIR, DB_DIR, ASSETS_DIR, STORE_DIR, THUMBS_DIR, MARKET_DIR, ENV_DIR, ENCRYPTED_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

USERS_DB = os.path.join(DB_DIR, "users.json")
FILES_DB = os.path.join(DB_DIR, "files.json")
SETTINGS_DB = os.path.join(DB_DIR, "settings.json")
STORE_DB = os.path.join(DB_DIR, "store.json")
ADMINS_DB = os.path.join(DB_DIR, "admins.json")
MARKET_DB = os.path.join(DB_DIR, "market.json")
SECURITY_DB = os.path.join(DB_DIR, "security.json")

db_lock = threading.Lock()
cancel_states = {}
last_bot_messages = {}
active_processes = {}
process_hours = {}
user_notifications = {}
admin_steps = {}

def read_json(path):
    with db_lock:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            return {}
        except:
            return {}

def write_json(path, data):
    with db_lock:
        try:
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            os.replace(temp_path, path)
        except Exception as e:
            print(f"JSON write error: {e}")

# نظام الحماية المتقدم للأكواد ضد الاختراق والتخريب
def scan_code_security(content):
    dangerous_patterns = [
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bshutil\.rmtree\s*\(\s*[\"\"]\/",
        r"\bctypes\b",
        r"open\s*\(\s*[\"\"].*\/etc\/passwd",
        r"open\s*\(\s*[\"\"].*\/root\/",
        r"rm\s+-rf\s+/",
        r"\bsubprocess\.Popen\s*\(\s*\[\s*[\"\"]rm",
        r"\beval\s*\(",
        r"\bexec\s*\("
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False, "⚠️ تم رفض الملف حظراً أمنياً لاحتوائه على أكواد خطيرة أو محاولات اختراق."
    return True, "الكود آمن"

def init_security():
    security = read_json(SECURITY_DB)
    if "master_key" not in security:
        m_key = base64.b64encode(get_random_bytes(32)).decode("utf-8")
        security["master_key"] = m_key
        security["file_keys"] = {}
        write_json(SECURITY_DB, security)

def get_master_key():
    security = read_json(SECURITY_DB)
    master_key = security.get("master_key")
    if not master_key:
        master_key = base64.b64encode(get_random_bytes(32)).decode("utf-8")
        security["master_key"] = master_key
        write_json(SECURITY_DB, security)
    return base64.b64decode(master_key)

def generate_file_key(fid, user_id, admin_id, token):
    security = read_json(SECURITY_DB)
    file_keys = security.get("file_keys", {})
    if fid not in file_keys:
        combined = f"{fid}:{user_id}:{admin_id}:{token}"
        salt = hashlib.sha256(combined.encode()).digest()[:16]
        master_key = get_master_key()
        kdf = hashlib.pbkdf2_hmac("sha256", master_key, salt, 100000, dklen=32)
        file_keys[fid] = {
            "key": base64.b64encode(kdf).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "user_id": user_id
        }
        security["file_keys"] = file_keys
        write_json(SECURITY_DB, security)
    return file_keys[fid]

def get_file_key(fid):
    security = read_json(SECURITY_DB)
    file_keys = security.get("file_keys", {})
    return file_keys.get(fid)

def encrypt_file_content(content, fid, user_id, admin_id, token):
    try:
        file_key_info = generate_file_key(fid, user_id, admin_id, token)
        key = base64.b64decode(file_key_info["key"])
        salt = base64.b64decode(file_key_info["salt"])
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content.encode("utf-8"), AES.block_size))
        encrypted_data = {
            "iv": base64.b64encode(cipher.iv).decode("utf-8"),
            "ciphertext": base64.b64encode(ct_bytes).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "fid": fid,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat()
        }
        return json.dumps(encrypted_data)
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_file_content(encrypted_json, fid):
    try:
        data = json.loads(encrypted_json)
        file_key_info = get_file_key(fid)
        if not file_key_info:
            return None
        key = base64.b64decode(file_key_info["key"])
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ciphertext"])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def save_encrypted_file(fid, content, user_id, admin_id, token):
    encrypted_content = encrypt_file_content(content, fid, user_id, admin_id, token)
    if encrypted_content:
        encrypted_path = os.path.join(ENCRYPTED_DIR, f"{fid}.enc")
        with open(encrypted_path, "w", encoding="utf-8") as f:
            f.write(encrypted_content)
        return True
    return False

def load_encrypted_file(fid):
    encrypted_path = os.path.join(ENCRYPTED_DIR, f"{fid}.enc")
    if os.path.exists(encrypted_path):
        with open(encrypted_path, "r", encoding="utf-8") as f:
            encrypted_content = f.read()
        return decrypt_file_content(encrypted_content, fid)
    return None

def auto_fix_errors(code):
    fixes = [
        (r"\bprint\s+(\S+)", r"print(\1)"),
        (r"\praw_input\b", "input"),
        (r"\bxrange\b", "range"),
        (r"\.iteritems\(\)", ".items()"),
        (r"\.itervalues\(\)", ".values()"),
        (r"\.iterkeys\(\)", ".keys()"),
    ]
    for pattern, replacement in fixes:
        code = re.sub(pattern, replacement, code)
    return code

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = "ZIAD_HOST_GOLD_2026_SUPER_SECRET_KEY"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BOT_TOKEN = "9198716816:AAHYWvbY4SwwBQ5hKnoA17SOuxlA851oNCY"
ADMIN_TELEGRAM_IDS = [1002670694]
ADMIN_ID = 1002670694
API_BASE_URL = os.environ.get("API_BASE_URL", "https://ehabrane701-lang.github.io/ehab-10/")

DEVELOPER_INFO = "🛠 طُوِّر بواسطة: *𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜*\n📬 تواصل: @Y_20_20"

def notify_admin(message: str):
    try:
        for admin_id in ADMIN_TELEGRAM_IDS:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": admin_id, "text": message, "parse_mode": "Markdown"},
                timeout=3
            )
    except Exception:
        pass

LANDING_HTML_CONTENT = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIAD HOST | استضافة احترافية</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #0a0a0a; color: #ffffff; overflow-x: hidden; }
        .hero-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #0a0a0a 100%); }
        .glow-orb { position: fixed; width: 600px; height: 600px; background: radial-gradient(circle, rgba(255, 215, 0, 0.15), transparent 70%); border-radius: 50%; top: -200px; right: -200px; z-index: -1; animation: floatGlow 20s ease-in-out infinite; }
        .glow-orb-2 { position: fixed; width: 500px; height: 500px; background: radial-gradient(circle, rgba(255, 100, 0, 0.1), transparent 70%); border-radius: 50%; bottom: -150px; left: -150px; z-index: -1; animation: floatGlow 25s ease-in-out infinite reverse; }
        @keyframes floatGlow { 0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.5; } 50% { transform: translate(50px, 30px) scale(1.1); opacity: 0.8; } }
        .grid-pattern { position: fixed; inset: 0; background-image: linear-gradient(rgba(255, 215, 0, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 215, 0, 0.03) 1px, transparent 1px); background-size: 60px 60px; z-index: -1; }
        .navbar { position: fixed; top: 0; width: 100%; padding: 20px 40px; background: rgba(10, 10, 10, 0.95); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255, 215, 0, 0.2); display: flex; justify-content: space-between; align-items: center; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 45px; height: 45px; background: linear-gradient(145deg, #1a1a2e, #0a0a0a); border: 1.5px solid #FFD700; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; color: #FFD700; box-shadow: 0 0 20px rgba(255, 215, 0, 0.3); }
        .logo-text { font-size: 1.6rem; font-weight: 800; background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .nav-buttons { display: flex; gap: 16px; }
        .nav-btn { padding: 10px 28px; border-radius: 50px; font-weight: 600; font-size: 0.9rem; cursor: pointer; transition: all 0.3s; border: none; font-family: 'Tajawal', sans-serif; }
        .nav-btn.login { background: transparent; border: 1.5px solid rgba(255, 215, 0, 0.5); color: #FFD700; }
        .nav-btn.login:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .nav-btn.register { background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; box-shadow: 0 4px 15px rgba(255, 215, 0, 0.3); }
        .nav-btn.register:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255, 215, 0, 0.4); }
        .hero { min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 100px 20px 60px; }
        .hero-content { max-width: 900px; }
        .hero-badge { display: inline-block; background: rgba(255, 215, 0, 0.15); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 50px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; margin-bottom: 30px; }
        .hero-title { font-size: 3.5rem; font-weight: 800; margin-bottom: 20px; line-height: 1.3; }
        .hero-title .highlight { background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .hero-subtitle { font-size: 1.2rem; color: #9ca3cf; margin-bottom: 40px; line-height: 1.8; }
        .hero-buttons { display: flex; gap: 20px; justify-content: center; flex-wrap: wrap; }
        .btn-primary { padding: 14px 40px; font-size: 1rem; font-weight: 700; border-radius: 50px; border: none; cursor: pointer; transition: all 0.3s; font-family: 'Tajawal', sans-serif; background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; box-shadow: 0 4px 20px rgba(255, 215, 0, 0.3); }
        .btn-primary:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(255, 215, 0, 0.5); }
        .btn-secondary { padding: 14px 40px; font-size: 1rem; font-weight: 700; border-radius: 50px; border: 1.5px solid rgba(255, 215, 0, 0.5); background: transparent; color: #FFD700; cursor: pointer; transition: all 0.3s; font-family: 'Tajawal', sans-serif; }
        .btn-secondary:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .features { padding: 80px 40px; background: rgba(0, 0, 0, 0.6); }
        .section-title { text-align: center; font-size: 2.2rem; font-weight: 700; margin-bottom: 50px; }
        .section-title span { color: #FFD700; }
        .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .feature-card { background: rgba(20, 20, 40, 0.8); backdrop-filter: blur(10px); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 28px; padding: 35px 25px; text-align: center; transition: all 0.3s; }
        .feature-card:hover { border-color: rgba(255, 215, 0, 0.5); transform: translateY(-8px); }
        .feature-icon { width: 70px; height: 70px; background: linear-gradient(145deg, #FFD70020, #FFA50010); border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 2rem; color: #FFD700; }
        .feature-card h3 { font-size: 1.3rem; margin-bottom: 12px; }
        .feature-card p { color: #9ca3cf; font-size: 0.85rem; line-height: 1.6; }
        .pricing { padding: 80px 40px; }
        .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .pricing-card { background: rgba(15, 15, 30, 0.9); backdrop-filter: blur(10px); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 32px; padding: 35px; text-align: center; transition: all 0.3s; position: relative; }
        .pricing-card.popular { border-color: #FFD700; transform: scale(1.02); box-shadow: 0 10px 40px rgba(255, 215, 0, 0.2); }
        .popular-badge { position: absolute; top: -12px; right: 50%; transform: translateX(50%); background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; padding: 5px 20px; border-radius: 50px; font-size: 0.7rem; font-weight: 700; }
        .plan-name { font-size: 1.5rem; font-weight: 700; margin-bottom: 15px; }
        .plan-price { font-size: 2.5rem; font-weight: 800; color: #FFD700; margin-bottom: 20px; }
        .plan-price small { font-size: 0.9rem; color: #9ca3cf; }
        .plan-features { list-style: none; margin: 25px 0; }
        .plan-features li { padding: 8px 0; color: #b9c3e0; font-size: 0.85rem; }
        .plan-features i { color: #FFD700; margin-left: 8px; }
        .stats-section { padding: 60px 40px; background: linear-gradient(135deg, #0a0a0a, #0f0f1a); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 30px; max-width: 1000px; margin: 0 auto; text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: 800; color: #FFD700; }
        .stat-label { color: #9ca3cf; margin-top: 8px; }
        .footer { padding: 40px; text-align: center; border-top: 1px solid rgba(255, 215, 0, 0.1); color: #6b7aaa; font-size: 0.8rem; }
        @media (max-width: 768px) { .navbar { padding: 15px 20px; } .logo-text { font-size: 1.2rem; } .hero-title { font-size: 2rem; } .hero-subtitle { font-size: 1rem; } .features, .pricing, .stats-section { padding: 50px 20px; } .nav-buttons { gap: 8px; } .nav-btn { padding: 6px 16px; font-size: 0.8rem; } }
    </style>
</head>
<body>
<div class="hero-bg"></div>
<div class="glow-orb"></div>
<div class="glow-orb-2"></div>
<div class="grid-pattern"></div>

<nav class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <span class="logo-text">ZIAD HOST</span>
    </div>
    <div class="nav-buttons">
        <button class="nav-btn login" onclick="window.location.href='/login'">تسجيل الدخول</button>
        <button class="nav-btn register" onclick="window.location.href='/login'">إنشاء حساب</button>
    </div>
</nav>

<section class="hero">
    <div class="hero-content">
        <div class="hero-badge"><i class="fas fa-bolt"></i> أقوى منصة استضافة في الشرق الأوسط</div>
        <h1 class="hero-title">استضف مشاريعك<br>بأعلى <span class="highlight">أداء وأمان</span></h1>
        <p class="hero-subtitle">منصة ZIAD HOST توفر لك بيئة استضافة متكاملة لبوتات تيليجرام ومواقع Node.js<br>مع دعم فني 24/7 وأسعار تنافسية</p>
        <div class="hero-buttons">
            <button class="btn-primary" onclick="window.location.href='/login'"><i class="fas fa-rocket"></i> ابدأ الآن مجاناً</button>
            <button class="btn-secondary" onclick="scrollToFeatures()"><i class="fas fa-info-circle"></i> تعرف على المميزات</button>
        </div>
    </div>
</section>

<section class="features" id="features">
    <h2 class="section-title">لماذا <span>ZIAD HOST</span>؟</h2>
    <div class="features-grid">
        <div class="feature-card">
            <div class="feature-icon"><i class="fab fa-python"></i></div>
            <h3>Python & Node.js</h3>
            <p>دعم كامل لجميع أنواع البوتات والتطبيقات مع أحدث الإصدارات</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-cloud-upload-alt"></i></div>
            <h3>رفع سهل وسريع</h3>
            <p>ارفع ملفاتك عبر السحب والإفلات أو من خلال مدير الملفات المتطور</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
            <h3>حماية متطورة</h3>
            <p>أنظمة أمان متعددة الطبقات لحماية مشاريعك وبياناتك</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-headset"></i></div>
            <h3>دعم فني 24/7</h3>
            <p>فريق دعم متخصص يجيب على استفساراتك في أي وقت</p>
        </div>
    </div>
</section>

<section class="pricing">
    <h2 class="section-title">خطط <span>استضافة</span> تناسب الجميع</h2>
    <div class="pricing-grid">
        <div class="pricing-card">
            <div class="plan-name">🎁 مجاني</div>
            <div class="plan-price">0$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> مساحة تخزين عالية</li>
                <li><i class="fas fa-check"></i> 256 MB رام</li>
                <li><i class="fas fa-check"></i> 0.5 CPU نواة</li>
                <li><i class="fas fa-check"></i> 2 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني</li>
            </ul>
        </div>
        <div class="pricing-card popular">
            <div class="popular-badge"><i class="fas fa-star"></i> الأكثر طلباً</div>
            <div class="plan-name">💎 4 جيجا</div>
            <div class="plan-price">5$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> 4 GB مساحة تخزين</li>
                <li><i class="fas fa-check"></i> 1024 MB رام</li>
                <li><i class="fas fa-check"></i> 1 CPU نواة</li>
                <li><i class="fas fa-check"></i> 5 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني + دعم أولوية</li>
            </ul>
        </div>
        <div class="pricing-card">
            <div class="plan-name">💎 10 جيجا</div>
            <div class="plan-price">10$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> 10 GB مساحة تخزين</li>
                <li><i class="fas fa-check"></i> 2048 MB رام</li>
                <li><i class="fas fa-check"></i> 2 CPU نواة</li>
                <li><i class="fas fa-check"></i> 10 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني + دعم VIP</li>
            </ul>
        </div>
    </div>
</section>

<section class="stats-section">
    <div class="stats-grid">
        <div><div class="stat-number">500+</div><div class="stat-label">مستخدم نشط</div></div>
        <div><div class="stat-number">1000+</div><div class="stat-label">سيرفر مستضاف</div></div>
        <div><div class="stat-number">99.9%</div><div class="stat-label">وقت تشغيل</div></div>
        <div><div class="stat-number">24/7</div><div class="stat-label">دعم فني</div></div>
    </div>
</section>

<footer class="footer">
    <p><i class="fas fa-crown"></i> ZIAD HOST - منصة الاستضافة الأقوى في الشرق الأوسط</p>
    <p style="margin-top: 12px;">© 2026 جميع الحقوق محفوظة | تصميم وتطوير ZIAD</p>
</footer>

<script>
    function scrollToFeatures() {
        document.getElementById('features').scrollIntoView({ behavior: 'smooth' });
    }
</script>
</body>
</html>
"""

LOGIN_HTML_CONTENT = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIAD HOST | تسجيل الدخول</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #000000; min-height: 100vh; display: flex; align-items: center; justify-content: center; position: relative; }
        .bg-gold { position: fixed; inset: 0; background: radial-gradient(ellipse at 30% 40%, rgba(255,215,0,0.1), transparent 70%); z-index: -2; }
        .login-card { background: rgba(5,5,5,0.95); backdrop-filter: blur(20px); border: 1px solid rgba(255,215,0,0.3); border-radius: 32px; padding: 40px; width: 90%; max-width: 450px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo-icon { width: 70px; height: 70px; background: linear-gradient(145deg, #000, #0a0a0a); border: 1.5px solid #FFD700; border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 15px; font-size: 2rem; color: #FFD700; }
        .logo-text { font-size: 1.5rem; font-weight: 800; background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .tabs { display: flex; gap: 8px; margin-bottom: 25px; background: rgba(0,0,0,0.5); border-radius: 60px; padding: 4px; }
        .tab-btn { flex: 1; padding: 10px; border-radius: 50px; border: none; background: none; color: #9ca3cf; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .tab-btn.active { background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; }
        .form-group { margin-bottom: 20px; }
        .form-group input { width: 100%; padding: 14px 18px; background: #000; border: 1px solid rgba(255,215,0,0.3); border-radius: 16px; color: white; font-family: 'Tajawal', sans-serif; font-size: 0.9rem; outline: none; }
        .form-group input:focus { border-color: #FFD700; }
        .submit-btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #FFD700, #FFA500); border: none; border-radius: 16px; color: #000; font-weight: 700; font-size: 1rem; cursor: pointer; transition: 0.2s; }
        .submit-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(255,215,0,0.4); }
        .alert { background: rgba(255,61,90,0.15); border: 1px solid rgba(255,61,90,0.4); border-radius: 12px; padding: 12px; margin-bottom: 20px; color: #ff7a94; font-size: 0.8rem; display: none; }
        .footer-note { text-align: center; margin-top: 20px; font-size: 0.7rem; color: #6b7aaa; }
        .footer-note a { color: #FFD700; text-decoration: none; }
        @media (max-width: 500px) { .login-card { padding: 30px 20px; } }
    </style>
</head>
<body>
<div class="bg-gold"></div>
<div class="login-card">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <div class="logo-text">ZIAD HOST</div>
    </div>
    
    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('login')">تسجيل الدخول</button>
        <button class="tab-btn" onclick="switchTab('register')">حساب جديد</button>
    </div>
    
    <div id="alertBox" class="alert"></div>
    
    <div id="loginForm">
        <div class="form-group"><input type="email" id="loginEmail" placeholder="البريد الإلكتروني"></div>
        <div class="form-group"><input type="password" id="loginPassword" placeholder="كلمة المرور"></div>
        <button class="submit-btn" onclick="doLogin()"><i class="fas fa-sign-in-alt"></i> دخول</button>
    </div>
    
    <div id="registerForm" style="display:none;">
        <div class="form-group"><input type="email" id="regEmail" placeholder="البريد الإلكتروني"></div>
        <div class="form-group"><input type="password" id="regPassword" placeholder="كلمة المرور (4 أحرف على الأقل)"></div>
        <button class="submit-btn" onclick="doRegister()"><i class="fas fa-user-plus"></i> إنشاء حساب</button>
    </div>
    
    <div class="footer-note">
        <i class="fas fa-shield-alt"></i> ZIAD HOST | استضافة آمنة
    </div>
</div>

<script>
    function showAlert(msg, isError=true) {
        const alert = document.getElementById('alertBox');
        alert.innerHTML = `<i class="fas ${isError ? 'fa-exclamation-circle' : 'fa-check-circle'}"></i> ${msg}`;
        alert.style.display = 'block';
        setTimeout(() => alert.style.display = 'none', 4000);
    }
    
    function switchTab(tab) {
        document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
        document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
        document.querySelectorAll('.tab-btn').forEach((btn, i) => {
            btn.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'register' && i === 1));
        });
    }
    
    async function doLogin() {
        const email = document.getElementById('loginEmail').value.trim().toLowerCase();
        const password = document.getElementById('loginPassword').value.trim();
        if(!email || !password) { showAlert('الرجاء إدخال جميع البيانات'); return; }
        try {
            const res = await fetch('/api/login', { method: 'POST', headers:{ 'Content-Type': 'application/json' }, body:JSON.stringify({email, password}) });
            const data = await res.json();
            if(data.success) { window.location.href = data.redirect; }
            else { showAlert(data.message || 'بيانات غير صحيحة'); }
        } catch(e) { showAlert('خطأ في الاتصال'); }
    }
    
    async function doRegister() {
        const email = document.getElementById('regEmail').value.trim().toLowerCase();
        const password = document.getElementById('regPassword').value.trim();
        if(!email || !password) { showAlert('الرجاء إدخال جميع البيانات'); return; }
        if(password.length < 4) { showAlert('كلمة المرور يجب أن تكون 4 أحرف على الأقل'); return; }
        try {
            const res = await fetch('/api/register', { method: 'POST', headers:{ 'Content-Type': 'application/json' }, body:JSON.stringify({email, password}) });
            const data = await res.json();
            if(data.success) {
                showAlert('✅ تم إنشاء الحساب! يمكنك تسجيل الدخول', false);
                switchTab('login');
                document.getElementById('loginEmail').value = email;
            } else {
                showAlert(data.message || 'فشل إنشاء الحساب');
            }
        } catch(e) { showAlert('خطأ في الاتصال'); }
    }
    
    fetch('/api/current_user').then(r=>r.json()).then(d=>{ if(d.success) window.location.href = d.is_admin ? '/admin' : '/dashboard'; }).catch(()=>{});
</script>
</body>
</html>
"""

INDEX_HTML_CONTENT = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>ZIAD HOST | لوحة التحكم</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #0a0a0a; color: #ffffff; overflow-x: hidden; }
        .bg-gradient { position: fixed; inset: 0; background: radial-gradient(ellipse at 20% 30%, rgba(255, 215, 0, 0.06), transparent 60%), radial-gradient(ellipse at 80% 70%, rgba(255, 255, 255, 0.02), transparent 70%); z-index: -2; }
        .bg-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px); background-size: 50px 50px; z-index: -1; }
        .navbar { background: rgba(10, 10, 10, 0.98); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255, 215, 0, 0.2); padding: 12px 28px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 38px; height: 38px; background: linear-gradient(145deg, #1a1a1a, #0a0a0a); border: 1px solid #FFD700; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1rem; color: #FFD700; }
        .logo-text { font-size: 1.2rem; font-weight: 700; color: #ffffff; }
        .logo-text span { color: #FFD700; }
        .user-section { display: flex; align-items: center; gap: 18px; }
        .user-greeting { font-size: 0.8rem; color: #888888; }
        .user-greeting strong { color: #FFD700; }
        .logout-btn { background: rgba(255, 70, 85, 0.1); border: 1px solid rgba(255, 70, 85, 0.3); color: #ff5e7c; padding: 6px 16px; border-radius: 40px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
        .logout-btn:hover { background: rgba(255, 70, 85, 0.2); }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 32px; }
        .stat-card { background: rgba(15, 15, 15, 0.9); backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.15); border-radius: 20px; padding: 20px; transition: all 0.3s; }
        .stat-card:hover { border-color: rgba(255, 215, 0, 0.4); transform: translateY(-3px); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .stat-title { font-size: 0.7rem; text-transform: uppercase; color: #888888; }
        .stat-icon { width: 40px; height: 40px; background: rgba(255, 215, 0, 0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1rem; color: #FFD700; }
        .stat-value { font-size: 1.6rem; font-weight: 700; margin-top: 8px; }
        .stat-progress { height: 4px; background: rgba(255, 255, 255, 0.1); border-radius: 10px; overflow: hidden; margin-top: 8px; }
        .stat-progress-bar { height: 100%; background: linear-gradient(90deg, #FFD700, #FFA500); width: 0%; }
        .servers-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 16px; }
        .servers-title { font-size: 1rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }
        .servers-title i { color: #FFD700; }
        .create-server-btn { background: #FFD700; border: none; border-radius: 40px; padding: 10px 24px; font-weight: 700; font-size: 0.8rem; color: #000000; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
        .create-server-btn:hover { background: #FFC107; transform: translateY(-2px); }
        .servers-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 24px; }
        .server-card { background: rgba(15, 15, 15, 0.9); backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.15); border-radius: 24px; overflow: hidden; transition: all 0.3s; cursor: pointer; }
        .server-card:hover { border-color: rgba(255, 215, 0, 0.4); transform: translateY(-5px); }
        .server-card-header { padding: 18px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255, 215, 0, 0.1); }
        .server-icon { width: 45px; height: 45px; background: rgba(255, 215, 0, 0.1); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; }
        .server-icon.python { color: #3776AB; }
        .server-icon.nodejs { color: #68A063; }
        .server-status { display: flex; align-items: center; gap: 6px; font-size: 0.7rem; background: rgba(0, 0, 0, 0.5); padding: 5px 12px; border-radius: 30px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .dot-online { background: #00ff88; box-shadow: 0 0 5px #00ff88; }
        .dot-offline { background: #666666; }
        .status-online { color: #00ff88; }
        .status-offline { color: #888888; }
        .server-name { font-size: 1rem; font-weight: 700; padding: 16px 20px 0 20px; }
        .server-meta { display: flex; gap: 12px; padding: 8px 20px; font-size: 0.7rem; color: #888888; flex-wrap: wrap; }
        .server-meta span { background: rgba(255, 255, 255, 0.05); padding: 4px 12px; border-radius: 30px; }
        .server-stats { display: flex; gap: 16px; padding: 12px 20px; font-size: 0.7rem; color: #aaaaaa; border-top: 1px solid rgba(255, 215, 0, 0.08); border-bottom: 1px solid rgba(255, 215, 0, 0.08); }
        .server-actions { display: flex; gap: 8px; padding: 16px 20px; justify-content: space-between; flex-wrap: wrap; }
        .action-group { display: flex; gap: 6px; flex-wrap: wrap; }
        .action-btn { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 30px; padding: 6px 14px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; transition: 0.2s; color: #cccccc; }
        .action-btn i { font-size: 0.7rem; }
        .action-btn.start:hover { background: rgba(0, 255, 136, 0.15); border-color: #00ff88; color: #00ff88; }
        .action-btn.stop:hover { background: rgba(255, 61, 90, 0.15); border-color: #ff3d5a; color: #ff3d5a; }
        .action-btn.restart:hover { background: rgba(255, 215, 0, 0.15); border-color: #FFD700; color: #FFD700; }
        .action-btn.delete:hover { background: rgba(255, 61, 90, 0.15); border-color: #ff3d5a; color: #ff3d5a; }
        .action-btn.detail:hover { background: rgba(255, 215, 0, 0.15); border-color: #FFD700; color: #FFD700; }
        .server-detail { display: none; animation: fadeIn 0.3s ease; }
        .server-detail.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .detail-header { background: rgba(15, 15, 15, 0.95); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 50px; padding: 12px 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        .back-btn { background: rgba(255, 215, 0, 0.1); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 40px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; }
        .server-type { background: rgba(255, 215, 0, 0.1); border-radius: 40px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; }
        .detail-actions { display: flex; gap: 12px; flex-wrap: wrap; }
        .glow-btn { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 40px; padding: 8px 20px; font-size: 0.75rem; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; transition: 0.2s; }
        .glow-btn.start { color: #00ff88; border-color: #00ff88; }
        .glow-btn.stop { color: #ff5e7c; border-color: #ff5e7c; }
        .glow-btn.restart { color: #FFD700; border-color: #FFD700; }
        .glow-btn.delete { color: #ff8a5c; border-color: #ff8a5c; }
        .glow-btn:hover { transform: translateY(-2px); background: rgba(255, 215, 0, 0.1); }
        .tabs-nav { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 1px solid rgba(255, 215, 0, 0.15); padding-bottom: 12px; flex-wrap: wrap; }
        .tab-nav-btn { background: none; border: none; padding: 10px 24px; font-size: 0.85rem; font-weight: 600; color: #888888; cursor: pointer; transition: 0.2s; border-radius: 40px; }
        .tab-nav-btn.active { background: rgba(255, 215, 0, 0.15); color: #FFD700; }
        .tab-pane { display: none; animation: fadeIn 0.2s; }
        .tab-pane.active { display: block; }
        .console-box { background: #050505; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 16px; padding: 20px; height: 500px; overflow-y: auto; font-family: monospace; font-size: 0.75rem; color: #00ff88; white-space: pre-wrap; }
        .files-table { width: 100%; border-collapse: collapse; }
        .files-table th, .files-table td { padding: 12px 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); text-align: right; }
        .files-table th { color: #888888; font-weight: 500; font-size: 0.75rem; }
        .upload-zone { border: 1px dashed rgba(255, 215, 0, 0.4); border-radius: 16px; padding: 30px; text-align: center; margin-bottom: 20px; cursor: pointer; transition: 0.2s; }
        .upload-zone:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.03); }
        .modal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.95); backdrop-filter: blur(12px); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: #111111; border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 24px; width: 90%; max-width: 500px; padding: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 0.8rem; color: #888888; }
        .form-group input, .form-group select, textarea { width: 100%; padding: 12px 16px; background: #0a0a0a; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 12px; color: white; font-family: 'Tajawal', sans-serif; outline: none; }
        .form-group input:focus, .form-group select:focus, textarea:focus { border-color: #FFD700; }
        .server-type-selector { display: flex; gap: 15px; margin: 20px 0; }
        .type-option { flex: 1; padding: 15px; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 16px; text-align: center; cursor: pointer; transition: 0.2s; }
        .type-option.selected { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .type-option i { font-size: 1.5rem; display: block; margin-bottom: 8px; }
        .toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: #1a1a1a; border: 1px solid #FFD700; border-radius: 50px; padding: 10px 24px; z-index: 1100; display: none; font-size: 0.8rem; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 12px; } .servers-grid { grid-template-columns: 1fr; } .container { padding: 16px; } .detail-header { flex-direction: column; align-items: stretch; border-radius: 20px; } .detail-actions { justify-content: center; } }
    </style>
</head>
<body>
<div class="bg-gradient"></div>
<div class="bg-grid"></div>

<div class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <div class="logo-text">ZIAD<span>HOST</span></div>
    </div>
    <div class="user-section">
        <div class="user-greeting"><i class="far fa-user-circle"></i> مرحباً، <strong id="userEmail">...</strong></div>
        <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> خروج</button>
    </div>
</div>

<div class="container">
    <div id="homeView">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">الخوادم المستخدمة</span><div class="stat-icon"><i class="fas fa-server"></i></div></div>
                <div class="stat-value" id="usedServers">0/0</div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">الصلاحية المتبقية</span><div class="stat-icon"><i class="fas fa-calendar-alt"></i></div></div>
                <div class="stat-value" id="expiryDays">-- يوم</div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">المساحة المستخدمة</span><div class="stat-icon"><i class="fas fa-hdd"></i></div></div>
                <div class="stat-value" id="diskUsed">0 MB</div>
                <div class="stat-progress"><div class="stat-progress-bar" id="diskProgress"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">استخدام الرام</span><div class="stat-icon"><i class="fas fa-microchip"></i></div></div>
                <div class="stat-value" id="ramUsage">0%</div>
                <div class="stat-progress"><div class="stat-progress-bar" id="ramProgress"></div></div>
            </div>
        </div>

        <div class="servers-header">
            <div class="servers-title"><i class="fas fa-cubes"></i> الخوادم النشطة</div>
            <button class="create-server-btn" id="openCreateModalBtn"><i class="fas fa-plus-circle"></i> خادم جديد</button>
        </div>

        <div class="servers-grid" id="serversGrid"><div style="text-align:center; padding:60px; color:#666;">جاري التحميل...</div></div>
    </div>

    <div id="detailView" class="server-detail">
        <div class="detail-header">
            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <button class="back-btn" onclick="goHome()"><i class="fas fa-arrow-right"></i> رجوع</button>
                <div class="server-type" id="serverTypeBadge">🐍 Python</div>
            </div>
            <div class="detail-actions">
                <button class="glow-btn start" onclick="serverAction('start')"><i class="fas fa-play"></i> تشغيل</button>
                <button class="glow-btn restart" onclick="serverAction('restart')"><i class="fas fa-sync-alt"></i> إعادة</button>
                <button class="glow-btn stop" onclick="serverAction('stop')"><i class="fas fa-stop"></i> إيقاف</button>
                <button class="glow-btn delete" onclick="confirmDelete()"><i class="fas fa-trash"></i> حذف</button>
            </div>
        </div>

        <div class="tabs-nav">
            <button class="tab-nav-btn active" data-tab="console">🖥 كونسول</button>
            <button class="tab-nav-btn" data-tab="files">📁 ملفات</button>
            <button class="tab-nav-btn" data-tab="stats">📊 إحصائيات</button>
            <button class="tab-nav-btn" data-tab="settings">⚙ إعدادات</button>
            <button class="tab-nav-btn" data-tab="api">🔑 API</button>
        </div>

        <div id="consoleTab" class="tab-pane active"><div class="console-box" id="consoleOut"></div></div>

        <div id="filesTab" class="tab-pane">
            <div class="upload-zone" onclick="document.getElementById('fileUpload').click()" ondragover="event.preventDefault()" ondrop="handleDrop(event)">
                <i class="fas fa-cloud-upload-alt" style="font-size: 1.8rem; color: #FFD700; margin-bottom: 10px; display: block;"></i>
                <span>اسحب الملفات هنا أو انقر للرفع</span>
            </div>
            <input type="file" id="fileUpload" multiple style="display:none" onchange="uploadFiles(this.files)">
            <div style="display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;">
                <button class="glow-btn" onclick="showCreateFileModal()" style="background:#FFD700; color:#000;"><i class="fas fa-file"></i> ملف جديد</button>
                <button class="glow-btn" onclick="installPackages()" style="background:#FFD700; color:#000;"><i class="fas fa-cube"></i> تثبيت المكتبات</button>
                <button class="glow-btn" onclick="showCreateFolderModal()" style="background:#FFD700; color:#000;"><i class="fas fa-folder-plus"></i> مجلد جديد</button>
            </div>
            <table class="files-table">
                <thead><tr><th></th><th>الاسم</th><th>الحجم</th><th>الإجراءات</th></tr></thead>
                <tbody id="filesList"></tbody>
            </table>
        </div>

        <div id="statsTab" class="tab-pane">
            <div style="display: grid; grid-template-columns: repeat(2,1fr); gap: 16px;">
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-microchip"></i> CPU</div>
                    <div class="stat-value" id="cpuStat">0%</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="cpuProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-memory"></i> RAM</div>
                    <div class="stat-value" id="ramStat">0 MB</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="ramDetailProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-hdd"></i> التخزين</div>
                    <div class="stat-value" id="storageStat">0 MB</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="storageProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-clock"></i> وقت التشغيل</div>
                    <div class="stat-value" id="uptimeStat">0</div>
                </div>
            </div>
        </div>

        <div id="settingsTab" class="tab-pane">
            <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:24px; margin-bottom:20px;">
                <div><i class="fas fa-rocket"></i> ملف بدء التشغيل</div>
                <div style="display: flex; gap: 12px; margin-top: 15px; flex-wrap: wrap;">
                    <select id="startupFileSelect" style="flex:1; background:#0a0a0a; border:1px solid #FFD700; border-radius:40px; padding:10px 16px; color:white;"></select>
                    <button class="glow-btn" onclick="setStartupFile()">حفظ</button>
                </div>
            </div>
            <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:24px;">
                <div>الخطة: <span id="planDetails"></span></div>
                <div style="margin-top: 12px;">الرام الأقصى: <span id="ramLimit"></span> MB</div>
                <div>المساحة القصوى: <span id="storageLimit"></span> MB</div>
            </div>
        </div>

        <div id="apiTab" class="tab-pane">
            <div style="background:rgba(15,15,15,0.8); border-radius:24px; padding:28px;">
                <h3 style="margin-bottom:16px;"><i class="fas fa-key"></i> مفتاح API</h3>
                <div id="apiKeyDisplay" style="background:#050505; border-radius:50px; padding:14px 20px; font-family:monospace; word-break:break-all; border:1px solid #FFD700;">لا يوجد مفتاح</div>
                <button class="glow-btn" onclick="generateApiKey()" style="margin-top:20px; background:#FFD700; color:#000;"><i class="fas fa-sync-alt"></i> إنشاء مفتاح جديد</button>
            </div>
        </div>
    </div>
</div>

<div id="createServerModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700; margin-bottom:20px;"><i class="fas fa-rocket"></i> إنشاء خادم جديد</h3>
        <div class="form-group"><label>اسم السيرفر</label><input type="text" id="serverName" placeholder="أدخل اسم السيرفر"></div>
        <div class="server-type-selector">
            <div class="type-option" data-type="Python" onclick="selectType('Python')"><i class="fab fa-python"></i><div>Python</div></div>
            <div class="type-option" data-type="Node.js" onclick="selectType('Node.js')"><i class="fab fa-node-js"></i><div>Node.js</div></div>
        </div>
        <button class="glow-btn" onclick="createServer()" style="width:100%; margin-top:20px; background:#FFD700; color:#000;"><i class="fas fa-check"></i> إنشاء</button>
        <button class="glow-btn" onclick="closeCreateModal()" style="width:100%; margin-top:10px;">إلغاء</button>
    </div>
</div>

<div id="editorModal" class="modal">
    <div class="modal-content">
        <textarea id="editorContent" rows="12" style="width:100%; background:#0a0a0a; border:1px solid #FFD700; border-radius:12px; padding:12px; color:white;"></textarea>
        <button class="glow-btn" onclick="saveFile()" style="width:100%; margin-top:16px; background:#FFD700; color:#000;">حفظ</button>
        <button class="glow-btn" onclick="closeEditorModal()" style="width:100%; margin-top:10px;">إلغاء</button>
    </div>
</div>

<div id="createFileModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700;"><i class="fas fa-file"></i> ملف جديد</h3>
        <div class="form-group"><input type="text" id="newFileName" placeholder="اسم الملف"></div>
        <div class="form-group"><textarea id="newFileContent" rows="5" placeholder="محتوى الملف"></textarea></div>
        <button class="glow-btn" onclick="createNewFile()" style="background:#FFD700; color:#000;">إنشاء</button>
    </div>
</div>

<div id="createFolderModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700;"><i class="fas fa-folder-plus"></i> مجلد جديد</h3>
        <div class="form-group"><input type="text" id="newFolderName" placeholder="اسم المجلد"></div>
        <button class="glow-btn" onclick="createNewFolder()" style="background:#FFD700; color:#000;">إنشاء</button>
    </div>
</div>

<div id="confirmModal" class="modal">
    <div class="modal-content">
        <p id="confirmMessage"></p>
        <div style="display:flex; gap:12px; margin-top:20px;">
            <button class="glow-btn" id="confirmYesBtn" style="background:#ff3d5a;">تأكيد</button>
            <button class="glow-btn" onclick="closeConfirmModal()">إلغاء</button>
        </div>
    </div>
</div>

<div id="toast" class="toast"></div>

<script>
    let currentServer = null;
    let currentEditFile = null;
    let confirmCallback = null;
    let pollingInterval = null;
    let selectedType = "Python";

    function selectType(type) {
        selectedType = type;
        document.querySelectorAll('.type-option').forEach(opt => {
            if(opt.dataset.type === type) opt.classList.add('selected');
            else opt.classList.remove('selected');
        });
    }

    function showToast(msg, isSuccess = false) {
        const toast = document.getElementById('toast');
        toast.innerHTML = `<i class="fas ${isSuccess ? 'fa-check-circle' : 'fa-info-circle'}"></i> ${msg}`;
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 3000);
    }

    function showConfirm(msg, callback) {
        document.getElementById('confirmMessage').innerText = msg;
        confirmCallback = callback;
        document.getElementById('confirmModal').classList.add('active');
    }

    function closeConfirmModal() {
        document.getElementById('confirmModal').classList.remove('active');
        confirmCallback = null;
    }

    document.getElementById('confirmYesBtn').onclick = () => {
        if(confirmCallback) confirmCallback();
        closeConfirmModal();
    };

    async function logout() {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login';
    }

    async function checkAuth() {
        try {
            const res = await fetch('/api/current_user');
            const data = await res.json();
            if(!data.success) window.location.href = '/login';
            else {
                document.getElementById('userEmail').innerText = data.email;
                loadServers();
                loadSystemStats();
                setInterval(loadSystemStats, 10000);
            }
        } catch(e) { console.error(e); }
    }

    async function loadSystemStats() {
        try {
            const res = await fetch('/api/system/metrics');
            const data = await res.json();
            document.getElementById('ramUsage').innerText = data.memory + '%';
            document.getElementById('ramProgress').style.width = data.memory + '%';
            if(document.getElementById('cpuStat')) {
                document.getElementById('cpuStat').innerText = data.cpu + '%';
                document.getElementById('cpuProgress').style.width = data.cpu + '%';
            }
        } catch(e) {}
    }

    async function loadServers() {
        try {
            const res = await fetch('/api/servers');
            const data = await res.json();
            if(!data.success) return;

            document.getElementById('usedServers').innerHTML = `${data.stats.used}/${data.stats.total || 2}`;
            document.getElementById('expiryDays').innerHTML = `${data.stats.expiry || '--'} يوم`;
            const diskTotal = data.stats.disk_total || 512000;
            const diskUsed = data.stats.disk_used || 0;
            document.getElementById('diskUsed').innerHTML = `${Math.round(diskUsed)}/${Math.round(diskTotal/1024)} MB`;
            document.getElementById('diskProgress').style.width = Math.min((diskUsed/diskTotal)*100, 100) + '%';

            const grid = document.getElementById('serversGrid');
            if(!data.servers || data.servers.length === 0) {
                grid.innerHTML = '<div style="text-align:center; padding:60px; color:#666;">لا توجد خوادم، أنشئ واحداً</div>';
                return;
            }

            grid.innerHTML = '';
            data.servers.forEach(s => {
                const typeIcon = s.server_type === 'Node.js' ? '<i class="fab fa-node-js"></i>' : '<i class="fab fa-python"></i>';
                const typeClass = s.server_type === 'Node.js' ? 'nodejs' : 'python';
                const card = document.createElement('div');
                card.className = 'server-card';
                card.innerHTML = `
                    <div class="server-card-header">
                        <div class="server-icon ${typeClass}">${typeIcon}</div>
                        <div class="server-status ${s.status==='Running'?'status-online':'status-offline'}">
                            <span class="status-dot ${s.status==='Running'?'dot-online':'dot-offline'}"></span>${s.status==='Running'?'يعمل':'متوقف'}
                        </div>
                    </div>
                    <div class="server-name">${escapeHtml(s.title)}</div>
                    <div class="server-meta">
                        <span><i class="fas fa-plug"></i> المنفذ: ${s.port||'N/A'}</span>
                        <span><i class="fas fa-tag"></i> ${s.plan==='free'?'مجاني':s.plan}</span>
                    </div>
                    <div class="server-stats">
                        <span><i class="fas fa-hdd"></i> ${Math.round((s.storage_limit||512000)/1024)} MB</span>
                        <span><i class="fas fa-microchip"></i> ${s.cpu_limit||0.5}</span>
                        <span><i class="fas fa-clock"></i> ${s.uptime || '0'}</span>
                    </div>
                    <div class="server-actions">
                        <div class="action-group">
                            <button class="action-btn start" data-action="start" data-folder="${s.folder}"><i class="fas fa-play"></i> تشغيل</button>
                            <button class="action-btn restart" data-action="restart" data-folder="${s.folder}"><i class="fas fa-sync-alt"></i> إعادة</button>
                            <button class="action-btn stop" data-action="stop" data-folder="${s.folder}"><i class="fas fa-stop"></i> إيقاف</button>
                        </div>
                        <div class="action-group">
                            <button class="action-btn delete" data-action="delete" data-folder="${s.folder}"><i class="fas fa-trash"></i> حذف</button>
                            <button class="action-btn detail" data-action="detail" data-folder="${s.folder}"><i class="fas fa-chevron-left"></i> تفاصيل</button>
                        </div>
                    </div>
                `;
                card.onclick = (e) => { if(!e.target.closest('.action-btn')) openServer(s); };
                card.querySelectorAll('.action-btn').forEach(btn => {
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        const action = btn.dataset.action;
                        const folder = btn.dataset.folder;
                        if(action === 'detail') openServer(s);
                        else performAction(folder, action);
                    };
                });
                grid.appendChild(card);
            });
        } catch(e) { console.error(e); }
    }

    async function performAction(folder, action) {
        if(action === 'delete' && !confirm('⚠️ حذف الخادم نهائياً؟')) return;
        showToast(`جاري ${action}...`);
        try {
            const res = await fetch(`/api/server/action/${folder}/${action}`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast(data.message || 'تم بنجاح', true);
                if(action !== 'delete') loadServers();
                else location.reload();
            } else showToast(data.message || 'فشل', false);
        } catch(e) { showToast('خطأ في الاتصال', false); }
    }

    function openServer(server) {
        currentServer = server;
        document.getElementById('homeView').style.display = 'none';
        document.getElementById('detailView').classList.add('active');
        
        const typeIcon = server.server_type === 'Node.js' ? '<i class="fab fa-node-js"></i>' : '<i class="fab fa-python"></i>';
        document.getElementById('serverTypeBadge').innerHTML = `${typeIcon} ${server.server_type || 'Python'} | ${escapeHtml(server.title)}`;
        document.getElementById('ramLimit').innerHTML = (server.ram_limit || 256) + ' MB';
        document.getElementById('storageLimit').innerHTML = Math.round((server.storage_limit || 512000)/1024) + ' MB';
        document.getElementById('planDetails').innerHTML = server.plan === 'free' ? 'مجاني' : server.plan;
        
        if(pollingInterval) clearInterval(pollingInterval);
        loadServerStats();
        pollingInterval = setInterval(loadServerStats, 4000);
        loadFiles();
        loadStartupFiles();
        loadApiKey();
        
        document.querySelectorAll('.tab-nav-btn').forEach((btn, idx) => {
            btn.classList.toggle('active', idx === 0);
        });
        document.querySelectorAll('.tab-pane').forEach((pane, idx) => {
            pane.classList.toggle('active', idx === 0);
        });
    }

    async function loadServerStats() {
        if(!currentServer) return;
        try {
            const res = await fetch(`/api/server/stats/${currentServer.folder}`);
            const data = await res.json();
            if(!data.success) return;
            
            const consoleOut = document.getElementById('consoleOut');
            consoleOut.innerHTML = (data.logs || 'لا توجد مخرجات').split('\\n').map(l => `<div>${escapeHtml(l)}</div>`).join('');
            consoleOut.scrollTop = consoleOut.scrollHeight;
            
            const ramLimit = currentServer.ram_limit || 256;
            const mem = parseFloat(data.mem) || 0;
            document.getElementById('ramStat').innerHTML = `${mem} / ${ramLimit} MB`;
            document.getElementById('ramDetailProgress').style.width = Math.min((mem/ramLimit)*100, 100) + '%';
            document.getElementById('uptimeStat').innerHTML = data.uptime || '0';
        } catch(e) {}
    }

    async function serverAction(action) {
        if(action === 'delete') { confirmDelete(); return; }
        showToast(`جاري ${action}...`);
        try {
            const res = await fetch(`/api/server/action/${currentServer.folder}/${action}`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast(data.message, true);
                setTimeout(loadServerStats, 1000);
                loadServers();
            } else showToast(data.message, false);
        } catch(e) { showToast('خطأ', false); }
    }

    function confirmDelete() {
        showConfirm('⚠️ حذف الخادم نهائياً؟ لا يمكن التراجع', async () => {
            const res = await fetch(`/api/server/action/${currentServer.folder}/delete`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast('تم الحذف', true);
                if(pollingInterval) clearInterval(pollingInterval);
                goHome();
            } else showToast(data.message, false);
        });
    }

    function goHome() {
        document.getElementById('homeView').style.display = 'block';
        document.getElementById('detailView').classList.remove('active');
        if(pollingInterval) clearInterval(pollingInterval);
        currentServer = null;
        loadServers();
    }

    document.querySelectorAll('.tab-nav-btn').forEach(btn => {
        btn.onclick = () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.getElementById(`${tab}Tab`).classList.add('active');
            if(tab === 'files') loadFiles();
            if(tab === 'settings') loadStartupFiles();
            if(tab === 'api') loadApiKey();
        };
    });

    async function loadFiles() {
        if(!currentServer) return;
        const tbody = document.getElementById('filesList');
        tbody.innerHTML = '<tr><td colspan="4">جاري...</td></tr>';
        try {
            const res = await fetch(`/api/files/list/${currentServer.folder}`);
            const files = await res.json();
            if(files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">لا توجد ملفات</td></tr>';
                return;
            }
            tbody.innerHTML = files.map(f => `
                <tr>
                    <td><i class="fas ${f.is_dir ? 'fa-folder' : 'fa-file'}"></i></td>
                    <td>${escapeHtml(f.name)}</td>
                    <td>${f.size}</td>
                    <td>
                        ${!f.is_dir ? `<button class="action-btn" onclick="editFile('${escapeHtml(f.name)}')"><i class="fas fa-edit"></i></button>` : ''}
                        <button class="action-btn" onclick="renameFile('${escapeHtml(f.name)}')"><i class="fas fa-i-cursor"></i></button>
                        ${f.name.toLowerCase().endsWith('.zip') ? `<button class="action-btn" onclick="unzipFile('${escapeHtml(f.name)}')"><i class="fas fa-file-archive"></i></button>` : ''}
                        <button class="action-btn" onclick="deleteFile('${escapeHtml(f.name)}')" style="color:#ff5e7c;"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        } catch(e) { tbody.innerHTML = '<tr><td colspan="4">خطأ</td></tr>'; }
    }

    function editFile(name) {
        currentEditFile = name;
        fetch(`/api/files/content/${currentServer.folder}/${name}`)
            .then(res => res.json())
            .then(data => {
                document.getElementById('editorContent').value = data.content || '';
                document.getElementById('editorModal').classList.add('active');
            });
    }

    function saveFile() {
        const content = document.getElementById('editorContent').value;
        fetch(`/api/files/save/${currentServer.folder}/${currentEditFile}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        }).then(() => {
            showToast('تم الحفظ', true);
            document.getElementById('editorModal').classList.remove('active');
            loadFiles();
        });
    }

    function closeEditorModal() {
        document.getElementById('editorModal').classList.remove('active');
    }

    function deleteFile(name) {
        showConfirm(`حذف ${name}؟`, async () => {
            await fetch(`/api/files/delete/${currentServer.folder}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ names: [name] })
            });
            loadFiles();
        });
    }

    function renameFile(name) {
        const newName = prompt('أدخل الاسم الجديد:', name);
        if(newName && newName !== name) {
            fetch(`/api/files/rename/${currentServer.folder}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_name: name, new_name: newName })
            }).then(() => loadFiles());
        }
    }

    function uploadFiles(files) {
        if(!files.length) return;
        const fd = new FormData();
        for(let f of files) fd.append('files[]', f);
        fetch(`/api/files/upload/${currentServer.folder}`, { method: 'POST', body: fd })
            .then(() => { loadFiles(); showToast('تم رفع الملفات', true); });
    }

    function handleDrop(e) {
        e.preventDefault();
        uploadFiles(e.dataTransfer.files);
    }

    function unzipFile(name) {
        showToast('جاري فك الضغط...');
        fetch(`/api/files/unzip/${currentServer.folder}/${name}`, { method: 'POST' })
            .then(() => { loadFiles(); showToast('تم فك الضغط', true); });
    }

    function installPackages() {
        fetch(`/api/server/install/${currentServer.folder}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => showToast(data.message, data.success));
    }

    function showCreateFileModal() {
        document.getElementById('newFileName').value = '';
        document.getElementById('newFileContent').value = '';
        document.getElementById('createFileModal').classList.add('active');
    }

    function createNewFile() {
        const name = document.getElementById('newFileName').value.trim();
        const content = document.getElementById('newFileContent').value;
        if(!name) return;
        fetch(`/api/files/create/${currentServer.folder}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: name, content })
        }).then(() => {
            document.getElementById('createFileModal').classList.remove('active');
            loadFiles();
            loadStartupFiles();
        });
    }

    function showCreateFolderModal() {
        document.getElementById('newFolderName').value = '';
        document.getElementById('createFolderModal').classList.add('active');
    }

    function createNewFolder() {
        const name = document.getElementById('newFolderName').value.trim();
        if(!name) return;
        fetch(`/api/files/create/${currentServer.folder}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: name, content: '' })
        }).then(() => {
            document.getElementById('createFolderModal').classList.remove('active');
            loadFiles();
        });
    }

    async function loadStartupFiles() {
        if(!currentServer) return;
        const res = await fetch(`/api/files/list/${currentServer.folder}`);
        const files = await res.json();
        const ext = currentServer.server_type === 'Node.js' ? '.js' : '.py';
        const codeFiles = files.filter(f => f.name.endsWith(ext) && !f.is_dir);
        const select = document.getElementById('startupFileSelect');
        select.innerHTML = '<option value="">-- اختر ملف التشغيل --</option>' +
            codeFiles.map(f => `<option value="${f.name}" ${currentServer.startup_file === f.name ? 'selected' : ''}>${f.name}</option>`).join('');
    }

    function setStartupFile() {
        const filename = document.getElementById('startupFileSelect').value;
        if(!filename) return;
        fetch(`/api/server/set-startup/${currentServer.folder}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        }).then(() => showToast('تم تعيين ملف التشغيل', true));
    }

    async function loadApiKey() {
        try {
            const res = await fetch('/api/current_user');
            const data = await res.json();
            if(data.api_key) document.getElementById('apiKeyDisplay').innerHTML = data.api_key;
            else document.getElementById('apiKeyDisplay').innerHTML = 'لا يوجد مفتاح - اضغط إنشاء';
        } catch(e) {}
    }

    async function generateApiKey() {
        try {
            const res = await fetch('/api/create_api_key', { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                document.getElementById('apiKeyDisplay').innerHTML = data.api_key;
                showToast('تم إنشاء مفتاح API', true);
            } else showToast('فشل الإنشاء', false);
        } catch(e) { showToast('خطأ', false); }
    }

    function showCreateModal() {
        document.getElementById('serverName').value = '';
        selectType('Python');
        document.getElementById('createServerModal').classList.add('active');
    }

    function closeCreateModal() {
        document.getElementById('createServerModal').classList.remove('active');
    }

    async function createServer() {
        const name = document.getElementById('serverName').value.trim();
        if(!name) { showToast('الرجاء إدخال اسم السيرفر', false); return; }
        closeCreateModal();
        showToast('جاري إنشاء السيرفر...');
        try {
            const res = await fetch('/api/server/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, server_type: selectedType })
            });
            const data = await res.json();
            if(data.success) {
                showToast(data.message, true);
                loadServers();
            } else showToast(data.message, false);
        } catch(e) { showToast('خطأ في الاتصال', false); }
    }

    function escapeHtml(str) {
        return String(str).replace(/[&<>]/g, m => m === '&' ? '&amp;' : m === '<' ? '&lt;' : '&gt;');
    }

    document.getElementById('openCreateModalBtn').onclick = showCreateModal;
    checkAuth();
</script>
</body>
</html>
"""

ADMIN_HTML_CONTENT = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>لوحة المسؤول | 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', 'Tajawal', sans-serif; background: #0a0c10; color: #eef2ff; overflow-x: hidden; }
        .bg-cyber { position: fixed; inset: 0; background: radial-gradient(ellipse at 20% 40%, rgba(45, 122, 255, 0.12), transparent 70%), radial-gradient(ellipse at 80% 60%, rgba(0, 229, 255, 0.08), transparent 60%); z-index: -2; }
        .bg-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(45, 122, 255, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(45, 122, 255, 0.04) 1px, transparent 1px); background-size: 50px 50px; z-index: -1; }
        .navbar { background: rgba(8, 12, 28, 0.85); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(45, 122, 255, 0.3); padding: 12px 28px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 38px; height: 38px; background: linear-gradient(145deg, #0f172a, #0a0f1c); border: 1px solid #00e5ff; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 18px; color: #00e5ff; box-shadow: 0 0 12px rgba(0, 229, 255, 0.3); }
        .logo-text { font-size: 16px; font-weight: 900; letter-spacing: 2px; background: linear-gradient(135deg, #2d7aff, #00e5ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .user-section { display: flex; align-items: center; gap: 18px; }
        .admin-badge { background: rgba(45, 122, 255, 0.2); padding: 4px 12px; border-radius: 30px; font-size: 0.7rem; color: #2d7aff; }
        .logout-btn { background: rgba(255, 70, 85, 0.15); border: 1px solid rgba(255, 70, 85, 0.4); color: #ff5e7c; padding: 6px 16px; border-radius: 40px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
        .logout-btn:hover { background: rgba(255, 70, 85, 0.25); transform: translateY(-1px); }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 28px; }
        .stat-card { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(45, 122, 255, 0.2); border-radius: 24px; padding: 20px; transition: all 0.3s; }
        .stat-card:hover { border-color: rgba(45, 122, 255, 0.5); transform: translateY(-3px); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .stat-title { font-size: 0.7rem; text-transform: uppercase; color: #9ca3cf; }
        .stat-icon { width: 42px; height: 42px; background: rgba(45, 122, 255, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #2d7aff; }
        .stat-value { font-size: 2rem; font-weight: 700; color: white; }
        .stat-change { font-size: 0.7rem; margin-top: 8px; color: #00ff88; }
        .tabs-container { background: rgba(15, 23, 42, 0.5); border-radius: 20px; padding: 6px; display: flex; gap: 8px; margin-bottom: 28px; flex-wrap: wrap; }
        .tab-btn { background: transparent; border: none; padding: 12px 28px; border-radius: 16px; font-family: 'Tajawal', sans-serif; font-weight: 600; font-size: 0.85rem; color: #9ca3cf; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 8px; }
        .tab-btn i { font-size: 1rem; }
        .tab-btn.active { background: rgba(45, 122, 255, 0.2); color: #2d7aff; }
        .tab-btn:not(.active):hover { background: rgba(255, 255, 255, 0.05); color: #eef2ff; }
        .tab-content { display: none; animation: fadeSlide 0.3s ease; }
        .tab-content.active { display: block; }
        @keyframes fadeSlide { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .card { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(45, 122, 255, 0.15); border-radius: 28px; padding: 24px; margin-bottom: 24px; }
        .card-title { font-size: 1rem; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; color: #2d7aff; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 0.75rem; color: #9ca3cf; }
        .form-group input, .form-group select { width: 100%; padding: 12px 16px; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(45, 122, 255, 0.3); border-radius: 50px; color: white; font-family: 'Tajawal', sans-serif; outline: none; transition: 0.2s; }
        .form-group input:focus { border-color: #2d7aff; background: rgba(45, 122, 255, 0.05); }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .btn-primary { background: linear-gradient(135deg, #2d7aff, #1a5cd8); border: none; border-radius: 50px; padding: 12px 24px; color: white; font-weight: 700; font-size: 0.85rem; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 4px 14px rgba(45, 122, 255, 0.3); }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(45, 122, 255, 0.4); }
        .btn-secondary { background: rgba(45, 122, 255, 0.15); border: 1px solid rgba(45, 122, 255, 0.3); border-radius: 50px; padding: 8px 20px; color: #2d7aff; font-weight: 600; font-size: 0.75rem; cursor: pointer; transition: 0.2s; }
        .data-table { width: 100%; border-collapse: collapse; }
        .data-table th { text-align: right; padding: 14px 12px; color: #9ca3cf; font-weight: 500; font-size: 0.7rem; border-bottom: 1px solid rgba(45, 122, 255, 0.15); }
        .data-table td { padding: 14px 12px; border-bottom: 1px solid rgba(45, 122, 255, 0.08); font-size: 0.8rem; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 30px; font-size: 0.7rem; font-weight: 600; }
        .badge-admin { background: rgba(45, 122, 255, 0.2); color: #2d7aff; }
        .badge-user { background: rgba(0, 229, 255, 0.15); color: #00e5ff; }
        .action-btn { background: none; border: none; color: #ff5e7c; cursor: pointer; font-size: 1rem; margin: 0 4px; }
        .action-btn.edit { color: #2d7aff; }
        .search-box { position: relative; margin-bottom: 20px; }
        .search-box i { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); color: #9ca3cf; }
        .search-box input { width: 100%; padding: 12px 45px 12px 16px; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(45, 122, 255, 0.3); border-radius: 50px; color: white; }
        .chart-container { background: rgba(15, 23, 42, 0.5); border-radius: 24px; padding: 20px; margin-top: 20px; }
        canvas { max-height: 300px; }
        .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1e293b; border: 1px solid #2d7aff; border-radius: 60px; padding: 10px 24px; font-size: 0.75rem; z-index: 1100; display: none; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 12px; } .form-row { grid-template-columns: 1fr; } .tabs-container { flex-direction: column; } .tab-btn { justify-content: center; } }
    </style>
</head>
<body>
<div class="bg-cyber"></div>
<div class="bg-grid"></div>

<div class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <span class="logo-text">ZIAD HOST | ADMIN</span>
    </div>
    <div class="user-section">
        <span class="admin-badge"><i class="fas fa-shield-alt"></i> مسؤول</span>
        <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> خروج</button>
    </div>
</div>

<div class="container">
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">إجمالي المستخدمين</span><div class="stat-icon"><i class="fas fa-users"></i></div></div>
            <div class="stat-value" id="totalUsers">0</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> نشط</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">إجمالي السيرفرات</span><div class="stat-icon"><i class="fas fa-server"></i></div></div>
            <div class="stat-value" id="totalServers">0</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> قيد التشغيل</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">السيرفرات النشطة</span><div class="stat-icon"><i class="fas fa-play-circle"></i></div></div>
            <div class="stat-value" id="activeServers">0</div>
            <div class="stat-change"><i class="fas fa-check-circle"></i> نشطة</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">المساحة المستخدمة</span><div class="stat-icon"><i class="fas fa-hdd"></i></div></div>
            <div class="stat-value" id="totalDisk">0 GB</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> إجمالي</div>
        </div>
    </div>

    <div class="tabs-container">
        <button class="tab-btn active" data-tab="dashboard"><i class="fas fa-chart-pie"></i> لوحة التحكم</button>
        <button class="tab-btn" data-tab="users"><i class="fas fa-users-gear"></i> إدارة المستخدمين</button>
        <button class="tab-btn" data-tab="servers"><i class="fas fa-globe"></i> السيرفرات</button>
        <button class="tab-btn" data-tab="settings"><i class="fas fa-sliders-h"></i> الإعدادات</button>
        <button class="tab-btn" data-tab="analytics"><i class="fas fa-chart-line"></i> التحليلات</button>
        <button class="tab-btn" data-tab="plans"><i class="fas fa-gem"></i> الخطط</button>
    </div>

    <div id="dashboardTab" class="tab-content active">
        <div class="card">
            <div class="card-title"><i class="fas fa-chart-simple"></i> نظرة عامة</div>
            <p style="color:#9ca3cf; margin-bottom: 16px;">مرحباً في لوحة التحكم المركزية. يمكنك مراقبة وإدارة جميع جوانب المنصة.</p>
            <div class="chart-container"><canvas id="userGrowthChart"></canvas></div>
        </div>
        <div class="card">
            <div class="card-title"><i class="fas fa-clock"></i> آخر النشاطات</div>
            <p style="color:#9ca3cf;">آخر تحديث: <span id="lastUpdate" style="color:#2d7aff;">الآن</span></p>
        </div>
    </div>

    <div id="usersTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-user-plus"></i> إضافة مستخدم جديد</div>
            <div id="userAlert"></div>
            <div class="form-row">
                <div class="form-group"><label>اسم المستخدم (البريد الإلكتروني)</label><input type="text" id="newUsername" placeholder="admin@ziadhost.com"></div>
                <div class="form-group"><label>كلمة المرور</label><input type="password" id="newPassword" placeholder="أدخل كلمة المرور"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>عدد السيرفرات المسموح بها</label><input type="number" id="maxServers" placeholder="2" value="2" min="1" max="100"></div>
                <div class="form-group"><label>عدد الأيام (الصلاحية)</label><input type="number" id="expiryDays" placeholder="365" value="365" min="1" max="3650"></div>
            </div>
            <button class="btn-primary" onclick="createNewUser()"><i class="fas fa-sparkles"></i> إنشاء الحساب</button>
        </div>

        <div class="card">
            <div class="card-title"><i class="fas fa-list"></i> قائمة المستخدمين</div>
            <div class="search-box"><i class="fas fa-search"></i><input type="text" id="userSearch" placeholder="ابحث عن مستخدم..."></div>
            <table class="data-table">
                <thead><tr><th>اسم المستخدم</th><th>النوع</th><th>الخطة</th><th>السيرفرات</th><th>الصلاحية</th><th>تاريخ الإنشاء</th><th>الإجراءات</th></tr></thead>
                <tbody id="usersList"></tbody>
            </table>
        </div>
    </div>

    <div id="serversTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-server"></i> جميع السيرفرات</div>
            <div class="search-box"><i class="fas fa-search"></i><input type="text" id="serverSearch" placeholder="ابحث عن سيرفر..."></div>
            <table class="data-table">
                <thead><tr><th>اسم السيرفر</th><th>المالك</th><th>النوع</th><th>الحالة</th><th>تاريخ الإنشاء</th><th>الإجراءات</th></tr></thead>
                <tbody id="serversList"><tr><td colspan="6" style="text-align:center;">جاري التحميل...</td></tr></tbody>
            </table>
        </div>
    </div>

    <div id="settingsTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-cog"></i> إعدادات النظام</div>
            <div class="form-row">
                <div class="form-group"><label>اسم المنصة</label><input type="text" id="siteName" value="ZIAD HOST"></div>
                <div class="form-group"><label>الحد الأقصى للسيرفرات لكل مستخدم (افتراضي)</label><input type="number" id="globalMaxServers" value="2" min="1" max="100"></div>
            </div>
            <button class="btn-primary" onclick="saveSettings()"><i class="fas fa-save"></i> حفظ الإعدادات</button>
        </div>
    </div>

    <div id="analyticsTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-chart-line"></i> إحصائيات الاستخدام</div>
            <div class="chart-container"><canvas id="serversGrowthChart"></canvas></div>
        </div>
    </div>

    <div id="plansTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-gem"></i> خطط الاستضافة</div>
            <div class="form-row" id="plansList"></div>
            <div class="form-row" style="margin-top: 20px;">
                <div class="form-group"><label>معرف الخطة</label><input type="text" id="newPlanId" placeholder="gold"></div>
                <div class="form-group"><label>اسم الخطة</label><input type="text" id="newPlanName" placeholder="خطة ذهبية"></div>
            </div>
            <button class="btn-primary" onclick="addPlan()"><i class="fas fa-plus"></i> إضافة خطة جديدة</button>
        </div>
    </div>
</div>

<div id="toast" class="toast"></div>

<script>
    let usersChart = null;
    let serversChart = null;

    const showToast = (msg, type = 'info') => {
        const t = document.getElementById('toast');
        t.innerHTML = `<i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-info-circle'}"></i> ${msg}`;
        t.style.display = 'block';
        setTimeout(() => t.style.display = 'none', 3000);
    };

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab + 'Tab').classList.add('active');
            if (tab === 'users') loadUsers();
            if (tab === 'servers') loadAllServers();
            if (tab === 'analytics') loadAnalytics();
            if (tab === 'plans') loadPlans();
        });
    });

    async function loadDashboard() {
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            if (data.success) {
                document.getElementById('totalUsers').innerText = data.users.length;
                let totalServers = 0, activeServers = 0, totalDisk = 0;
                for (const user of data.users) {
                    const userServers = await fetch(`/api/servers?user=${encodeURIComponent(user.username)}`).then(r => r.json());
                    if (userServers.servers) {
                        totalServers += userServers.servers.length;
                        activeServers += userServers.servers.filter(s => s.status === 'Running').length;
                        totalDisk += userServers.stats?.disk_total || 0;
                    }
                }
                document.getElementById('totalServers').innerText = totalServers;
                document.getElementById('activeServers').innerText = activeServers;
                document.getElementById('totalDisk').innerText = (totalDisk / 1024).toFixed(1) + ' GB';
                document.getElementById('lastUpdate').innerText = new Date().toLocaleTimeString('ar-SA');
            }
        } catch (e) { console.log(e); }
    }

    async function loadUsers() {
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            const list = document.getElementById('usersList');
            list.innerHTML = data.users.map(u => `
                <tr>
                    <td><strong>${escapeHtml(u.username)}</strong></td>
                    <td><span class="badge ${u.is_admin ? 'badge-admin' : 'badge-user'}">${u.is_admin ? '👑 مسؤول' : '👤 مستخدم'}</span></td>
                    <td>${u.plan || 'free'}</td>
                    <td>${u.max_servers}</td>
                    <td>${u.expiry_days} يوم</td>
                    <td style="font-size:11px;">${(u.created_at || '').substring(0,10)}</td>
                    <td>
                        ${!u.is_admin ? `<button class="action-btn delete" onclick="deleteUser('${escapeHtml(u.username)}')"><i class="fas fa-trash"></i></button>` : '<span style="color:#9ca3cf;">محمي</span>'}
                    </td>
                </tr>
            `).join('');
            document.getElementById('userSearch').oninput = function() {
                const q = this.value.toLowerCase();
                list.querySelectorAll('tr').forEach(r => {
                    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            };
        } catch(e) { showToast('خطأ في تحميل المستخدمين', 'error'); }
    }

    async function loadAllServers() {
        const tbody = document.getElementById('serversList');
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">جاري التحميل...</td></tr>';
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            let allServers = [];
            for (const user of data.users) {
                const serversRes = await fetch(`/api/servers?user=${encodeURIComponent(user.username)}`);
                const serversData = await serversRes.json();
                if (serversData.servers) {
                    serversData.servers.forEach(s => {
                        allServers.push({ ...s, owner: user.username });
                    });
                }
            }
            if (allServers.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">لا توجد سيرفرات</td></tr>';
                return;
            }
            tbody.innerHTML = allServers.map(s => `
                <tr>
                    <td>${escapeHtml(s.title || s.name)}</td>
                    <td>${escapeHtml(s.owner)}</td>
                    <td>${s.server_type || 'Python'}</td>
                    <td><span class="badge ${s.status === 'Running' ? 'badge-admin' : ''}" style="${s.status !== 'Running' ? 'background:#555;' : ''}">${s.status === 'Running' ? '🟢 نشط' : '⚫ متوقف'}</span></td>
                    <td style="font-size:11px;">${(s.created_at || '').substring(0,10)}</td>
                    <td><button class="action-btn delete" onclick="deleteServer('${s.folder}')"><i class="fas fa-trash"></i></button></td>
                </tr>
            `).join('');
            document.getElementById('serverSearch').oninput = function() {
                const q = this.value.toLowerCase();
                tbody.querySelectorAll('tr').forEach(r => {
                    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            };
        } catch(e) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">خطأ في التحميل</td></tr>'; }
    }

    async function loadPlans() {
        try {
            const res = await fetch('/api/plans');
            const data = await res.json();
            if (data.success) {
                const container = document.getElementById('plansList');
                container.innerHTML = '';
                for (const [id, plan] of Object.entries(data.plans)) {
                    const planDiv = document.createElement('div');
                    planDiv.className = 'stat-card';
                    planDiv.style.cssText = 'background:rgba(15,23,42,0.5); border-radius:20px; padding:16px; flex:1; min-width:200px;';
                    planDiv.innerHTML = `
                        <div style="font-weight:700; margin-bottom:8px; color:#2d7aff;">${plan.name} (${id})</div>
                        <div>💰 ${plan.price === 0 ? 'مجاني' : plan.price + '$'}</div>
                        <div>💾 ${(plan.storage / 1024).toFixed(0)} GB</div>
                        <div>🧠 ${plan.ram} MB</div>
                        <div>🖥 ${plan.cpu} نواة</div>
                        <div>📦 حد أقصى: ${plan.max_servers} سيرفر</div>
                    `;
                    container.appendChild(planDiv);
                }
            }
        } catch(e) { console.error(e); }
    }

    async function createNewUser() {
        const username = document.getElementById('newUsername').value.trim();
        const password = document.getElementById('newPassword').value.trim();
        const max_servers = parseInt(document.getElementById('maxServers').value) || 2;
        const expiry_days = parseInt(document.getElementById('expiryDays').value) || 365;
        if (!username || !password) { showToast('⚠️ الرجاء إدخال جميع البيانات', 'error'); return; }
        try {
            const res = await fetch('/api/admin/create-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: username, password, max_servers, expiry_days })
            });
            const data = await res.json();
            if (data.success) {
                showToast('✅ تم إنشاء المستخدم بنجاح', 'success');
                document.getElementById('newUsername').value = '';
                document.getElementById('newPassword').value = '';
                loadUsers();
                loadDashboard();
            } else { showToast('❌ ' + (data.message || 'فشل الإنشاء'), 'error'); }
        } catch(e) { showToast('❌ خطأ في الاتصال', 'error'); }
    }

    async function deleteUser(username) {
        if (!confirm(`حذف المستخدم "${username}" نهائياً؟`)) return;
        try {
            const res = await fetch('/api/admin/delete-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: username })
            });
            const data = await res.json();
            if (data.success) {
                showToast('🗑️ تم حذف المستخدم', 'success');
                loadUsers();
                loadDashboard();
            } else { showToast('❌ ' + (data.message || 'فشل الحذف'), 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }

    async function deleteServer(folder) {
        if (!confirm(`حذف السيرفر نهائياً؟`)) return;
        try {
            const res = await fetch(`/api/server/action/${folder}/delete`, { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast('🗑️ تم حذف السيرفر', 'success');
                loadAllServers();
                loadDashboard();
            } else { showToast('❌ فشل الحذف', 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }

    function saveSettings() { showToast('✅ تم حفظ الإعدادات بنجاح', 'success'); }

    async function addPlan() {
        const plan_id = document.getElementById('newPlanId').value.trim().toLowerCase();
        const name = document.getElementById('newPlanName').value.trim();
        if (!plan_id || !name) { showToast('⚠️ الرجاء إدخال المعرف واسم الخطة', 'error'); return; }
        try {
            const res = await fetch('/api/admin/add-plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plan_id, name, price: 0, storage: 512000, ram: 256, cpu: 0.5, max_servers: 2 })
            });
            const data = await res.json();
            if (data.success) {
                showToast('✅ تم إضافة الخطة بنجاح', 'success');
                loadPlans();
                document.getElementById('newPlanId').value = '';
                document.getElementById('newPlanName').value = '';
            } else { showToast('❌ ' + (data.message || 'فشل الإضافة'), 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }

    async function loadAnalytics() {
        try {
            const metrics = await fetch('/api/system/metrics').then(r => r.json());
        } catch(e) {}
        if (usersChart) usersChart.destroy();
        if (serversChart) serversChart.destroy();
        const ctx1 = document.getElementById('userGrowthChart').getContext('2d');
        const ctx2 = document.getElementById('serversGrowthChart').getContext('2d');
        usersChart = new Chart(ctx1, { type: 'line', data: { labels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو'], datasets: [{ label: 'المستخدمين', data: [2, 4, 7, 10, 15, 20], borderColor: '#2d7aff', backgroundColor: 'rgba(45,122,255,0.1)', fill: true }] }, options: { responsive: true, maintainAspectRatio: true } });
        serversChart = new Chart(ctx2, { type: 'bar', data: { labels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو'], datasets: [{ label: 'السيرفرات', data: [1, 3, 5, 8, 12, 18], backgroundColor: '#2d7aff' }] }, options: { responsive: true, maintainAspectRatio: true } });
    }

    function logout() { fetch('/api/logout', { method: 'POST' }).then(() => window.location.href = '/login'); }
    function escapeHtml(s) { return String(s).replace(/[&<>]/g, m => m === '&' ? '&amp;' : m === '<' ? '&lt;' : '&gt;'); }

    loadDashboard();
    loadUsers();
    loadAnalytics();
    setInterval(() => { loadDashboard(); loadAnalytics(); }, 30000);
</script>
</body>
</html>
"""

with open(os.path.join(BASE_DIR, "landing.html"), "w", encoding="utf-8") as f:
    f.write(LANDING_HTML_CONTENT)

with open(os.path.join(BASE_DIR, "login.html"), "w", encoding="utf-8") as f:
    f.write(LOGIN_HTML_CONTENT)

with open(os.path.join(BASE_DIR, "index.html"), "w", encoding="utf-8") as f:
    f.write(INDEX_HTML_CONTENT)

with open(os.path.join(BASE_DIR, "admin_panel.html"), "w", encoding="utf-8") as f:
    f.write(ADMIN_HTML_CONTENT)

DB_FILE = os.path.join(BASE_DIR, "db.json")

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "plans" not in data:
                    data["plans"] = {}
                if "server_types" not in data:
                    data["server_types"] = ["Python", "Node.js"]
                if "pending_users" not in data:
                    data["pending_users"] = []
                return data
        except Exception:
            pass
    
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@ziadhost.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    admin_hash = hashlib.sha256(admin_password.encode()).hexdigest()
    
    default_db = {
        "users": {
            admin_email: {
                "password": admin_hash,
                "is_admin": True,
                "created_at": str(datetime.now()),
                "max_servers": 999999,
                "expiry_days": 3650,
                "last_login": None,
                "telegram_id": ADMIN_TELEGRAM_IDS[0],
                "api_key": None,
                "storage_limit": 10240,
                "plan": "admin"
            }
        },
        "servers": {},
        "logs": [],
        "pending_users": [],
        "plans": {
            "free": {"name": "🎁 مجاني", "storage": 512000, "ram": 256, "cpu": 0.5, "max_servers": 2, "price": 0},
            "4gb": {"name": "💎 4 جيجا", "storage": 4096000, "ram": 1024, "cpu": 1, "max_servers": 5, "price": 5},
            "10gb": {"name": "💎 10 جيجا", "storage": 10240000, "ram": 2048, "cpu": 2, "max_servers": 10, "price": 10}
        },
        "server_types": ["Python", "Node.js"]
    }
    save_db(default_db)
    return default_db

def save_db(db_data):
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db_data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ خطأ في حفظ DB: {e}")
        return False

db = load_db()

PORT_RANGE_START = 8100
PORT_RANGE_END = 9100

def get_assigned_port():
    used = set()
    for srv in db.get("servers", {}).values():
        if srv.get("port"):
            used.add(srv["port"])
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in used:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex(("127.0.0.1", port))
                s.close()
                if result != 0:
                    return port
            except Exception:
                return port
    return PORT_RANGE_START

def get_current_user():
    if "email" in session:
        return db["users"].get(session["email"])
    return None

def get_user_servers_dir(email):
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    path = os.path.join(USERS_DIR, safe_email, "SERVERS")
    os.makedirs(path, exist_ok=True)
    return path

def is_admin(email):
    u = db["users"].get(email)
    return u.get("is_admin", False) if u else False

def generate_api_key():
    return secrets.token_urlsafe(32)

def get_user_by_api_key(api_key):
    for email, udata in db["users"].items():
        if udata.get("api_key") == api_key:
            return email, udata
    return None, None

def uptime_str(start_time):
    if not start_time:
        return "0 ثانية"
    diff = time.time() - start_time
    days = int(diff // 86400)
    hours = int((diff % 86400) // 3600)
    mins = int((diff % 3600) // 60)
    parts = []
    if days > 0: parts.append(f"{days} يوم")
    if hours > 0: parts.append(f"{hours} ساعة")
    if mins > 0: parts.append(f"{mins} دقيقة")
    return " و ".join(parts) if parts else "أقل من دقيقة"

def _check_admin_access():
    if "email" in session and is_admin(session["email"]):
        return True
    api_key = None
    if request.is_json:
        try:
            api_key = request.get_json().get("api_key")
        except Exception:
            pass
    if not api_key:
        api_key = request.args.get("api_key")
    if api_key:
        email, user = get_user_by_api_key(api_key)
        if email and is_admin(email):
            return True
    return False

def detect_main_file(srv_path: str) -> str:
    for candidate in ["main.py", "bot.py", "app.py", "index.py", "run.py", "start.py"]:
        if os.path.exists(os.path.join(srv_path, candidate)):
            return candidate
    py_files = [f for f in os.listdir(srv_path) if f.endswith(".py")]
    return py_files[0] if py_files else ""

def auto_install_deps(srv_path: str, log_file):
    try:
        req = os.path.join(srv_path, "requirements.txt")
        if os.path.exists(req):
            log_file.write(f"\n📦 تثبيت requirements.txt...\n")
            log_file.flush()
            proc = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                cwd=srv_path, stdout=log_file, stderr=subprocess.STDOUT, env=os.environ.copy()
            )
            proc.wait(timeout=180)
            log_file.write("✅ تم تثبيت المكتبات\n")
    except Exception as e:
        log_file.write(f"\n⚠️ تثبيت تلقائي: {e}\n")
    log_file.flush()

def detect_node_main_file(srv_path: str) -> str:
    candidates = ["index.js", "server.js", "app.js", "main.js", "bot.js", "start.js"]
    for candidate in candidates:
        if os.path.exists(os.path.join(srv_path, candidate)):
            return candidate
    js_files = [f for f in os.listdir(srv_path) if f.endswith(".js")]
    return js_files[0] if js_files else ""

def auto_install_node_deps(srv_path: str, log_file):
    try:
        package_json = os.path.join(srv_path, "package.json")
        if os.path.exists(package_json):
            log_file.write(f"\n📦 تثبيت حزم Node.js...\n")
            log_file.flush()
            proc = subprocess.Popen(
                ["npm", "install"], cwd=srv_path, stdout=log_file, stderr=subprocess.STDOUT, env=os.environ.copy()
            )
            proc.wait(timeout=180)
            log_file.write("✅ تم تثبيت حزم Node.js\n")
    except Exception as e:
        log_file.write(f"\n⚠️ تثبيت تلقائي Node.js فشل: {e}\n")
    log_file.flush()

def start_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    if srv.get("server_type") == "Node.js":
        return start_node_server_process(folder)
    else:
        return start_python_server_process(folder)

def start_python_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    main_file = srv.get("startup_file", "")
    if not main_file:
        main_file = detect_main_file(srv["path"])
        if main_file:
            srv["startup_file"] = main_file
            save_db(db)
        else:
            return False, "لا يوجد ملف تشغيل Python (.py)"

    file_path = os.path.join(srv["path"], main_file)
    if not os.path.exists(file_path):
        return False, f"الملف {main_file} غير موجود"

    port = srv.get("port") or get_assigned_port()
    srv["port"] = port
    save_db(db)

    log_path = os.path.join(srv["path"], "out.log")
    error_path = os.path.join(srv["path"], "errors.log")
    log_file = open(log_path, "a", encoding="utf-8")
    log_file.write(f"\n{'='*50}\n🚀 بدء التشغيل (Python) - {datetime.now()}\n📁 {main_file}\n🔌 المنفذ: {port}\n{'='*50}\n\n")
    log_file.flush()

    try:
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["SERVER_PORT"] = str(port)
        cmd = [sys.executable, "-u", main_file]
        proc = subprocess.Popen(
            cmd, cwd=srv["path"], stdout=log_file, stderr=open(error_path, "a", encoding="utf-8"),
            env=env, preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        srv["status"] = "Running"
        srv["pid"] = proc.pid
        srv["start_time"] = time.time()
        save_db(db)
        return True, "✅ تم التشغيل"
    except Exception as e:
        log_file.write(f"\n❌ خطأ: {e}\n")
        log_file.close()
        return False, str(e)

def start_node_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    main_file = srv.get("startup_file", "")
    if not main_file:
        main_file = detect_node_main_file(srv["path"])
        if main_file:
            srv["startup_file"] = main_file
            save_db(db)
        else:
            return False, "لا يوجد ملف تشغيل JavaScript (.js)"

    file_path = os.path.join(srv["path"], main_file)
    if not os.path.exists(file_path):
        return False, f"الملف {main_file} غير موجود"

    port = srv.get("port") or get_assigned_port()
    srv["port"] = port
    save_db(db)

    log_path = os.path.join(srv["path"], "out.log")
    error_path = os.path.join(srv["path"], "errors.log")
    log_file = open(log_path, "a", encoding="utf-8")
    log_file.write(f"\n{'='*50}\n🚀 بدء التشغيل (Node.js) - {datetime.now()}\n📁 {main_file}\n🔌 المنفذ: {port}\n{'='*50}\n\n")
    log_file.flush()

    try:
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["SERVER_PORT"] = str(port)
        cmd = ["node", main_file]
        proc = subprocess.Popen(
            cmd, cwd=srv["path"], stdout=log_file, stderr=open(error_path, "a", encoding="utf-8"),
            env=env, preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        srv["status"] = "Running"
        srv["pid"] = proc.pid
        srv["start_time"] = time.time()
        save_db(db)
        return True, "✅ تم التشغيل"
    except Exception as e:
        log_file.write(f"\n❌ خطأ: {e}\n")
        log_file.close()
        return False, str(e)

def stop_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return
    if srv.get("pid"):
        try:
            p = psutil.Process(srv["pid"])
            if hasattr(os, 'killpg'):
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except Exception:
                    pass
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except Exception:
            pass
    srv["status"] = "Stopped"
    srv["pid"] = None
    save_db(db)

def restart_server(folder):
    stop_server_process(folder)
    time.sleep(2)
    start_server_process(folder)

def process_monitor():
    while True:
        try:
            for folder, srv in list(db["servers"].items()):
                if srv.get("status") == "Running" and srv.get("pid"):
                    try:
                        p = psutil.Process(srv["pid"])
                        if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
                            restart_server(folder)
                    except psutil.NoSuchProcess:
                        restart_server(folder)
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(15)

threading.Thread(target=process_monitor, daemon=True).start()

@app.route('/')
def home():
    if 'email' in session:
        if is_admin(session['email']):
            return redirect('/admin')
        return redirect('/dashboard')
    return send_from_directory(BASE_DIR, "landing.html")

@app.route('/login')
def login_page():
    if 'email' in session:
        return redirect('/')
    return send_from_directory(BASE_DIR, "login.html")

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')
    return send_from_directory(BASE_DIR, "index.html")

@app.route('/admin')
def admin_panel():
    if 'email' not in session or not is_admin(session['email']):
        return redirect('/login')
    return send_from_directory(BASE_DIR, "admin_panel.html")

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return jsonify({"success": False, "message": "جميع الحقول مطلوبة"})
    if '@' not in email or '.' not in email:
        return jsonify({"success": False, "message": "البريد الإلكتروني غير صالح"})
    if len(password) < 4:
        return jsonify({"success": False, "message": "كلمة المرور 4 أحرف على الأقل"})
    if email in db["users"]:
        return jsonify({"success": False, "message": "البريد الإلكتروني موجود بالفعل"})

    db["users"][email] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": db["plans"]["free"]["max_servers"],
        "expiry_days": 365,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": db["plans"]["free"]["storage"],
        "plan": "free"
    }
    save_db(db)
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    user_dir = os.path.join(USERS_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)

    threading.Thread(target=notify_admin, args=(f"🔔 *مستخدم جديد!*\n📧 {email}",), daemon=True).start()
    return jsonify({"success": True, "message": "✅ تم إنشاء حسابك بنجاح!"})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    user = db["users"].get(email)
    if user and user["password"] == hashlib.sha256(password.encode()).hexdigest():
        session.clear()
        session['email'] = email
        session.permanent = True
        user["last_login"] = str(datetime.now())
        save_db(db)
        is_adm = user.get("is_admin", False)
        return jsonify({"success": True, "redirect": "/admin" if is_adm else "/dashboard", "is_admin": is_adm})

    return jsonify({"success": False, "message": "بيانات غير صحيحة"})

@app.route('/api/logout', methods=['GET', 'POST'])
def api_logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/api/current_user')
def api_current_user():
    if 'email' in session:
        u = db["users"].get(session['email'])
        if u:
            return jsonify({
                "success": True,
                "email": session['email'],
                "username": session['email'],
                "is_admin": u.get("is_admin", False),
                "plan": u.get("plan", "free"),
                "api_key": u.get("api_key")
            })
    return jsonify({"success": False})

@app.route('/api/create_api_key', methods=['POST'])
def create_api_key_route():
    if 'email' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    email = session['email']
    new_key = generate_api_key()
    db["users"][email]["api_key"] = new_key
    save_db(db)
    return jsonify({"success": True, "api_key": new_key})

@app.route('/api/plans')
def get_plans():
    return jsonify({"success": True, "plans": db.get("plans", {})})

@app.route('/api/admin/users')
def admin_users():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    users_list = []
    for uemail, udata in db["users"].items():
        users_list.append({
            "email": uemail,
            "username": uemail,
            "is_admin": udata.get("is_admin", False),
            "created_at": udata.get("created_at"),
            "max_servers": udata.get("max_servers", 1),
            "expiry_days": udata.get("expiry_days", 365),
            "plan": udata.get("plan", "free")
        })
    return jsonify({"success": True, "users": users_list})

@app.route('/api/admin/create-user', methods=['POST'])
def admin_create_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    max_servers = int(data.get("max_servers", 2))
    expiry_days = int(data.get("expiry_days", 365))
    
    if not email or not password:
        return jsonify({"success": False, "message": "البريد وكلمة المرور مطلوبة"})
    if email in db["users"]:
        return jsonify({"success": False, "message": "المستخدم موجود بالفعل"})
    
    db["users"][email] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": max_servers,
        "expiry_days": expiry_days,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": db["plans"]["free"]["storage"],
        "plan": "free"
    }
    save_db(db)
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    user_dir = os.path.join(USERS_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
    
    return jsonify({"success": True, "message": "✅ تم إنشاء الحساب بنجاح"})

@app.route('/api/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    
    target_user = db["users"].get(email)
    if target_user and target_user.get("is_admin", False):
        return jsonify({"success": False, "message": "لا يمكن حذف الأدمن"})
    
    if email in db["users"]:
        for fid, srv in list(db["servers"].items()):
            if srv["owner"] == email:
                stop_server_process(fid)
                if os.path.exists(srv["path"]):
                    shutil.rmtree(srv["path"], ignore_errors=True)
                del db["servers"][fid]
        
        del db["users"][email]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم حذف المستخدم"})
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

@app.route('/api/admin/add-plan', methods=['POST'])
def admin_add_plan():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    plan_id = data.get("plan_id", "").strip().lower()
    name = data.get("name", "").strip()
    if not plan_id or not name:
        return jsonify({"success": False, "message": "معرف الخطة والاسم مطلوبان"})
    
    db["plans"][plan_id] = {
        "name": name,
        "price": float(data.get("price", 0)),
        "storage": int(data.get("storage", 512000)),
        "ram": int(data.get("ram", 256)),
        "cpu": float(data.get("cpu", 0.5)),
        "max_servers": int(data.get("max_servers", 2))
    }
    save_db(db)
    return jsonify({"success": True, "message": "✅ تم إضافة الخطة بنجاح"})

@app.route('/api/system/metrics')
def get_metrics():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/api/servers')
def list_servers():
    if 'email' not in session and not _check_admin_access():
        return jsonify({"success": False}), 401
    
    target_user = request.args.get("user")
    if target_user and is_admin(session.get('email', '')):
        owner_email = target_user
    else:
        owner_email = session.get('email')

    user_servers = []
    total_disk_used_mb = 0.0
    for folder, srv in db["servers"].items():
        if srv["owner"] == owner_email:
            disk_used = 0
            if os.path.exists(srv["path"]):
                try:
                    for root, dirs, files in os.walk(srv["path"]):
                        for f in files:
                            fp = os.path.join(root, f)
                            try:
                                disk_used += os.path.getsize(fp)
                            except Exception:
                                pass
                except Exception:
                    pass
            disk_used_mb = round(disk_used / (1024 * 1024), 2)
            total_disk_used_mb += disk_used_mb
            user_servers.append({
                "folder": folder,
                "title": srv["name"],
                "name": srv["name"],
                "server_type": srv.get("server_type", "Python"),
                "status": srv.get("status", "Stopped"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية",
                "port": srv.get("port", "N/A"),
                "plan": srv.get("plan", "free"),
                "storage_limit": srv.get("storage_limit", 512000),
                "ram_limit": srv.get("ram_limit", 256),
                "cpu_limit": srv.get("cpu_limit", 0.5),
                "disk_used": disk_used_mb,
                "startup_file": srv.get("startup_file", "")
            })
    user = db["users"].get(owner_email, {})
    return jsonify({
        "success": True,
        "servers": user_servers,
        "stats": {
            "used": len(user_servers),
            "total": user.get("max_servers", 2),
            "expiry": user.get("expiry_days", 365),
            "disk_used": round(total_disk_used_mb, 2),
            "disk_total": user.get("storage_limit", 512000),
        }
    })

@app.route('/api/server/add', methods=['POST'])
def add_server():
    if 'email' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    user = db["users"].get(session['email'])
    if not user:
        return jsonify({"success": False, "message": "مستخدم غير موجود"})
    
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == session['email']])
    if user_srv_count >= user.get("max_servers", 2):
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({user.get('max_servers', 2)}) سيرفر"})
    
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    server_type = data.get("server_type", "Python")
    
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"})
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    safe_email = session['email'].replace("@", "_at_").replace(".", "_dot_")
    folder = f"{safe_email}_{re.sub(r'[^a-zA-Z0-9]', '_', name)}_{int(time.time())}"
    path = os.path.join(get_user_servers_dir(session['email']), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name,
        "owner": session['email'],
        "path": path,
        "server_type": server_type,
        "status": "Stopped",
        "created_at": str(datetime.now()),
        "startup_file": "",
        "pid": None,
        "port": assigned_port,
        "plan": plan_id,
        "storage_limit": plan["storage"],
        "ram_limit": plan["ram"],
        "cpu_limit": plan["cpu"]
    }
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم إنشاء {server_type} سيرفر: {name}"})

@app.route('/api/server/action/<folder>/<action>', methods=['POST'])
def server_action(folder, action):
    email = session.get('email')
    srv = db["servers"].get(folder)
    if not srv:
        return jsonify({"success": False, "message": "السيرفر غير موجود"})
    if not is_admin(email) and srv["owner"] != email:
        return jsonify({"success": False, "message": "غير مصرح"})
    
    if action == "start":
        if srv.get("status") == "Running":
            return jsonify({"success": False, "message": "الخادم يعمل بالفعل"})
        ok, msg = start_server_process(folder)
        return jsonify({"success": ok, "message": msg})
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        restart_server(folder)
        return jsonify({"success": True, "message": "🔄 تم إعادة التشغيل"})
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False})

@app.route('/api/server/stats/<folder>')
def get_server_stats(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    status = srv.get("status", "Stopped")
    logs = "لا توجد مخرجات بعد"
    log_path = os.path.join(srv["path"], "out.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().split('\n')
                logs = '\n'.join(lines[-500:])
        except Exception:
            pass
    
    mem_info = "0"
    if srv.get("pid") and status == "Running":
        try:
            p = psutil.Process(srv["pid"])
            mem_info = f"{p.memory_info().rss / (1024*1024):.1f}"
        except Exception:
            pass
    
    return jsonify({
        "success": True,
        "status": status,
        "logs": logs,
        "mem": mem_info,
        "uptime": uptime_str(srv.get("start_time")) if status == "Running" else "0 ثانية",
        "port": srv.get("port", "--")
    })

@app.route('/api/files/list/<folder>')
def list_server_files(folder):
    if 'email' not in session:
        return jsonify([]), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify([])
    
    path = srv["path"]
    files = []
    try:
        for f in os.listdir(path):
            if f in ["out.log", "server.log", "meta.json", "errors.log"]:
                continue
            fpath = os.path.join(path, f)
            stat = os.stat(fpath)
            size_bytes = stat.st_size
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f} KB"
            else:
                size_str = f"{size_bytes/(1024*1024):.1f} MB"
            files.append({
                "name": f, "size": size_str, "is_dir": os.path.isdir(fpath),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    except Exception:
        pass
    return jsonify(sorted(files, key=lambda x: (not x['is_dir'], x['name'].lower())))

@app.route('/api/files/content/<folder>/<path:filename>')
def get_file_content(folder, filename):
    if 'email' not in session:
        return jsonify({"content": ""}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"content": ""})
    if '..' in filename:
        return jsonify({"content": ""})
    
    fpath = os.path.join(srv["path"], filename)
    if not os.path.exists(fpath) or os.path.isdir(fpath):
        return jsonify({"content": ""})
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": "[ملف ثنائي]"})

@app.route('/api/files/save/<folder>/<path:filename>', methods=['POST'])
def save_file_content(folder, filename):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    if '..' in filename:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    content = data.get("content", "")
    
    is_safe, msg = scan_code_security(content)
    if not is_safe:
        return jsonify({"success": False, "message": msg})

    fpath = os.path.join(srv["path"], filename)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True, "message": "✅ تم الحفظ بنجاح"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/upload/<folder>', methods=['POST'])
def upload_files(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    files = request.files.getlist('files[]')
    uploaded = 0
    for f in files:
        try:
            if f and f.filename and '..' not in f.filename:
                content_bytes = f.read()
                try:
                    content_str = content_bytes.decode("utf-8", errors="ignore")
                    is_safe, msg = scan_code_security(content_str)
                    if not is_safe:
                        continue
                except Exception:
                    pass
                
                save_path = os.path.join(srv["path"], f.filename)
                with open(save_path, "wb") as sf:
                    sf.write(content_bytes)
                uploaded += 1
        except Exception:
            pass
    
    if uploaded > 0:
        if srv.get("server_type") == "Node.js":
            threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
        else:
            threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
        return jsonify({"success": True, "message": f"✅ تم رفع {uploaded} ملف بأمان"})
    return jsonify({"success": False, "message": "فشل الرفع أو تم حظر الملفات"})

@app.route('/api/files/delete/<folder>', methods=['POST'])
def delete_files(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    names = data.get("names", data.get("name", []))
    if isinstance(names, str):
        names = [names]
    
    deleted = 0
    for name in names:
        if name and '..' not in name:
            fpath = os.path.join(srv["path"], name)
            try:
                if os.path.isdir(fpath):
                    shutil.rmtree(fpath)
                elif os.path.exists(fpath):
                    os.remove(fpath)
                deleted += 1
            except Exception:
                pass
    return jsonify({"success": True, "message": f"🗑 تم حذف {deleted} ملف"})

@app.route('/api/files/create/<folder>', methods=['POST'])
def create_file_api(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    filename = data.get("filename", "").strip()
    content = data.get("content", "")
    if not filename or '..' in filename:
        return jsonify({"success": False})
    
    is_safe, msg = scan_code_security(content)
    if not is_safe:
        return jsonify({"success": False, "message": msg})

    fpath = os.path.join(srv["path"], filename)
    try:
        if filename.endswith('/'):
            os.makedirs(fpath, exist_ok=True)
        else:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
        return jsonify({"success": True, "message": f"✅ تم إنشاء {filename}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/rename/<folder>', methods=['POST'])
def rename_file(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()
    if '..' in old_name or '..' in new_name:
        return jsonify({"success": False})
    
    old_path = os.path.join(srv["path"], old_name)
    new_path = os.path.join(srv["path"], new_name)
    if not os.path.exists(old_path):
        return jsonify({"success": False})
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True, "message": f"✅ تم تغيير الاسم"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/unzip/<folder>/<path:filename>', methods=['POST'])
def unzip_file(folder, filename):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    zip_path = os.path.join(srv["path"], filename)
    if not os.path.exists(zip_path):
        return jsonify({"success": False})
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(srv["path"])
        return jsonify({"success": True, "message": f"✅ تم فك الضغط"})
    except Exception:
        return jsonify({"success": False, "message": "فشل فك الضغط"})

@app.route('/api/server/set-startup/<folder>', methods=['POST'])
def set_startup_file(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    filename = data.get("filename", "").strip()
    if not filename or '..' in filename:
        return jsonify({"success": False})
    
    srv["startup_file"] = filename
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم تعيين {filename}"})

@app.route('/api/server/install/<folder>', methods=['POST'])
def install_requirements(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    if srv.get("server_type") == "Node.js":
        threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    else:
        threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    return jsonify({"success": True, "message": "📦 بدأ تثبيت المكتبات"})

@app.route('/api/bot/verify', methods=['POST'])
def bot_verify():
    data = request.get_json() or {}
    api_key = data.get('api_key', '').strip()
    if not api_key:
        return jsonify({"success": False})
    email, user = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False})
    return jsonify({
        "success": True, "email": email, "username": email,
        "is_admin": is_admin(email), "max_servers": user.get("max_servers", 2)
    })

@app.route('/api/bot/servers', methods=['GET'])
def bot_list_servers():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({"success": False}), 401
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    
    user_servers = []
    for folder, srv in db["servers"].items():
        if srv["owner"] == email:
            user_servers.append({
                "folder": folder, "title": srv["name"], "name": srv["name"],
                "status": srv.get("status", "Stopped"), "port": srv.get("port", "N/A"),
                "type": srv.get("server_type", "Python"), "server_type": srv.get("server_type", "Python"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية"
            })
    return jsonify({"success": True, "servers": user_servers})

@app.route('/api/bot/server/action', methods=['POST'])
def bot_server_action():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    action = data.get('action')
    if not all([api_key, folder, action]):
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    if action == "start":
        ok, msg = start_server_process(folder)
        return jsonify({"success": ok, "message": msg})
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        restart_server(folder)
        return jsonify({"success": True, "message": "🔄 تم إعادة التشغيل"})
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False})

@app.route('/api/bot/console', methods=['GET'])
def bot_console():
    api_key = request.args.get('api_key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    log_path = os.path.join(srv["path"], "out.log")
    logs = "لا توجد مخرجات بعد"
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()[-3500:]
        except Exception:
            pass
    return jsonify({"success": True, "logs": logs})

@app.route('/api/bot/errors', methods=['GET'])
def bot_errors():
    api_key = request.args.get('api_key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    err_path = os.path.join(srv["path"], "errors.log")
    errors = "✅ لا توجد أخطاء"
    if os.path.exists(err_path):
        try:
            with open(err_path, "r", encoding="utf-8", errors="ignore") as f:
                errors = f.read()[-3500:]
        except Exception:
            pass
    return jsonify({"success": True, "errors": errors})

@app.route('/api/bot/install', methods=['POST'])
def bot_install():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    if srv.get("server_type") == "Node.js":
        threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    else:
        threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    return jsonify({"success": True, "message": "📦 بدأ تثبيت المكتبات"})

@app.route('/api/bot/create_server', methods=['POST'])
def bot_create_server():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    email, user = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == email])
    if user_srv_count >= user.get("max_servers", 2):
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({user.get('max_servers', 2)}) سيرفر"})
    
    name = data.get("name", "").strip()
    server_type = data.get("server_type", "Python")
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"})
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    folder = f"{safe_email}_{re.sub(r'[^a-zA-Z0-9]', '_', name)}_{int(time.time())}"
    path = os.path.join(get_user_servers_dir(email), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name, "owner": email, "path": path, "server_type": server_type,
        "status": "Stopped", "created_at": str(datetime.now()), "startup_file": "",
        "pid": None, "port": assigned_port, "plan": plan_id,
        "storage_limit": plan["storage"], "ram_limit": plan["ram"], "cpu_limit": plan["cpu"]
    }
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم إنشاء {server_type} سيرفر: {name}"})

WAITING_FOR_API_KEY, WAITING_FOR_NEW_SERVER_NAME, WAITING_FOR_SERVER_TYPE, WAITING_FOR_DELETE_USERNAME = range(4)

def api_request(endpoint, method="GET", data=None, params=None, api_key=None):
    url = f"{API_BASE_URL}{endpoint}"
    try:
        if method == "GET":
            p = dict(params or {})
            if api_key: p["api_key"] = api_key
            resp = requests.get(url, params=p, timeout=30)
        else:
            d = dict(data or {})
            if api_key and "api_key" not in d: d["api_key"] = api_key
            resp = requests.post(url, json=d, timeout=30)
        return resp.json() if resp.ok else {"success": False, "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def is_admin_tg(update: Update) -> bool:
    return update.effective_chat.id in ADMIN_TELEGRAM_IDS

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("📚 المساعدة:\n\nهذا البوت يعمل بشكل مستمر على خادم ZIAD HOST\nللاشتراك أو الاستفسار: @Y_20_20")

async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("ℹ️ معلومات البوت:\n\n🤖 الخدمة: ZIAD HOST\n✅ الحالة: نشط ومستمر\n🛠 المطور: @Y_20_20")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_message = update.message.text
    await update.message.reply_text(f"📨 تم استقبال رسالتك:\n\n{user_message}\n\nشكراً لاستخدامك ZIAD HOST!\n🛠 @Y_20_20")

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(msg="Exception while handling an update:", exc_info=context.error)

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, edit=False):
    api_key = context.user_data.get("api_key")
    username = context.user_data.get("username", "")
    is_adm = is_admin_tg(update)

    keyboard = []
    if api_key:
        keyboard.append([
            InlineKeyboardButton("📁 سيرفراتي", callback_data="my_servers"),
            InlineKeyboardButton("➕ إنشاء سيرفر", callback_data="create_server"),
        ])
        keyboard.append([
            InlineKeyboardButton("🔑 تغيير API Key", callback_data="change_api"),
            InlineKeyboardButton("🚪 تسجيل خروج", callback_data="logout"),
        ])
    else:
        keyboard.append([InlineKeyboardButton("🔑 ربط API Key", callback_data="enter_api")])

    if is_adm:
        keyboard.append([InlineKeyboardButton("👑 لوحة الإدارة", callback_data="admin_panel")])

    keyboard.append([InlineKeyboardButton("💬 تواصل مع المطور @Y_20_20", url="https://t.me/Y_20_20")])

    text = "━━━━━━━━━━━━━━━━━━━━\n      ZIAD HOST 🚀\n━━━━━━━━━━━━━━━━━━━━\n"
    if username: text += f"👤 أهلاً، *{username}*!\n"
    text += "✅ متصل بالنظام\n" if api_key else "⚠️ يجب ربط API Key أولاً\n"
    text += f"\n{DEVELOPER_INFO}"

    markup = InlineKeyboardMarkup(keyboard)
    try:
        if edit and update.callback_query:
            await update.callback_query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
        elif update.message:
            await update.message.reply_text(text, parse_mode="Markdown", reply_markup=markup)
        else:
            await update.callback_query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
    except Exception:
        pass

async def show_servers_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    api_key = context.user_data.get("api_key")
    if not api_key:
        await query.edit_message_text("❌ يجب ربط API Key أولاً.")
        return

    result = api_request("/api/bot/servers", api_key=api_key)
    if not result or not result.get("success"):
        await query.edit_message_text("❌ فشل جلب السيرفرات. تحقق من صحة API Key.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]]))
        return

    servers = result.get("servers", [])
    if not servers:
        await query.edit_message_text("📭 لا توجد سيرفرات. أنشئ سيرفرك الأول الآن!", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("➕ إنشاء سيرفر", callback_data="create_server")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]
        ]))
        return

    await query.edit_message_text(f"📋 لديك *{len(servers)}* سيرفر:", parse_mode="Markdown")

    for srv in servers:
        status_emoji = "🟢" if srv["status"] == "Running" else "⚫"
        srv_type = srv.get("type", "Python")
        type_icon = "🐍" if srv_type == "Python" else "🟨"

        text = f"━━━━━━━━━━━━━━━━━━━━\n{status_emoji} *{srv['title']}*\n━━━━━━━━━━━━━━━━━━━━\n{type_icon} النوع: `{srv_type}`\n📊 الحالة: `{srv['status']}`\n🔌 المنفذ: `{srv['port']}`\n⏱ وقت التشغيل: {srv['uptime']}"
        folder = srv["folder"]
        keyboard = [
            [InlineKeyboardButton("▶️ تشغيل", callback_data=f"srv_start|{folder}"), InlineKeyboardButton("⏹ إيقاف", callback_data=f"srv_stop|{folder}"), InlineKeyboardButton("🔄 إعادة", callback_data=f"srv_restart|{folder}")],
            [InlineKeyboardButton("🖥 كونسول", callback_data=f"console|{folder}"), InlineKeyboardButton("⚠️ أخطاء", callback_data=f"errors|{folder}"), InlineKeyboardButton("🗑 حذف", callback_data=f"srv_delete|{folder}")],
            [InlineKeyboardButton("📦 تثبيت مكتبات تلقائياً", callback_data=f"install|{folder}")]
        ]
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

    await query.message.reply_text("━━━━━━━━━━━━━━━━━━━━", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]))

async def show_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if not is_admin_tg(update):
        await query.edit_message_text("❌ غير مصرح لك بالدخول.")
        return

    api_key = context.user_data.get("api_key")
    result = api_request("/api/admin/users", api_key=api_key)
    users = result.get("users", []) if result and result.get("success") else []

    text = f"━━━━━━━━━━━━━━━━━━━━\n  👑 لوحة إدارة ZIAD HOST\n━━━━━━━━━━━━━━━━━━━━\n👥 المستخدمين: *{len(users)}*\n━━━━━━━━━━━━━━━━━━━━\n"
    for u in users[:10]:
        text += f"• `{u['username']}` | {u.get('max_servers', 1)} سيرفر\n"

    keyboard = [
        [InlineKeyboardButton("📊 إحصائيات النظام", callback_data="admin_stats")],
        [InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]
    ]
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    api_key = context.user_data.get("api_key")
    if api_key:
        result = api_request("/api/bot/verify", method="POST", data={"api_key": api_key})
        if result and result.get("success"):
            context.user_data["username"] = result.get("username")
            await show_main_menu(update, context)
            return ConversationHandler.END
        context.user_data.clear()

    keyboard = [
        [InlineKeyboardButton("🔑 إدخال API Key", callback_data="enter_api")],
        [InlineKeyboardButton("💬 تواصل مع المطور @Y_20_20", url="https://t.me/Y_20_20")]
    ]
    await update.message.reply_text(
        "━━━━━━━━━━━━━━━━━━━━\n      ZIAD HOST 🚀\n━━━━━━━━━━━━━━━━━━━━\nللاشتراك والحصول على حساب:\n📬 تواصل مع المطور: @Y_20_20\n\n" + DEVELOPER_INFO,
        parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_API_KEY

async def handle_api_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    api_key = update.message.text.strip()
    result = api_request("/api/bot/verify", method="POST", data={"api_key": api_key})
    if not result or not result.get("success"):
        await update.message.reply_text("❌ *مفتاح API غير صالح!*\n\nتحقق من الكود وحاول مرة أخرى أو تواصل مع المطور: @Y_20_20", parse_mode="Markdown")
        return WAITING_FOR_API_KEY

    context.user_data["api_key"] = api_key
    context.user_data["username"] = result.get("username")
    context.user_data["is_admin"] = result.get("is_admin", False)

    await update.message.reply_text(f"✅ *تم الربط بنجاح!*\n👤 مرحباً *{result.get('username')}*!", parse_mode="Markdown")
    await show_main_menu(update, context)
    return ConversationHandler.END

async def receive_server_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.message.text.strip()
    context.user_data["pending_server_name"] = name
    keyboard = [
        [InlineKeyboardButton("🐍 Python", callback_data="server_type_python"), InlineKeyboardButton("🟨 Node.js", callback_data="server_type_nodejs")]
    ]
    await update.message.reply_text(f"📦 *اختر نوع السيرفر:*\n\nالاسم: `{name}`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    return WAITING_FOR_SERVER_TYPE

async def receive_server_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    srv_type = "Python" if query.data == "server_type_python" else "Node.js"
    name = context.user_data.get("pending_server_name", "Server")

    result = api_request("/api/bot/create_server", method="POST", data={
        "api_key": context.user_data["api_key"], "name": name, "server_type": srv_type
    })

    type_icon = "🐍" if srv_type == "Python" else "🟨"
    if result and result.get("success"):
        await query.edit_message_text(f"✅ *تم إنشاء السيرفر بنجاح!*\n\n📛 الاسم: `{name}`\n{type_icon} النوع: `{srv_type}`\n\nارفع ملفاتك عبر لوحة التحكم الآن.", parse_mode="Markdown")
    else:
        await query.edit_message_text(f"❌ *فشل الإنشاء!*\n{result.get('message', 'خطأ')}", parse_mode="Markdown")

    await show_main_menu(update, context)
    return ConversationHandler.END

async def show_console(update: Update, context: ContextTypes.DEFAULT_TYPE, folder: str):
    query = update.callback_query
    result = api_request("/api/bot/console", params={"folder": folder}, api_key=context.user_data.get("api_key"))
    if result and result.get("success"):
        logs = result.get("logs", "لا توجد مخرجات")
        if len(logs) > 3500: logs = "...\n" + logs[-3500:]
        keyboard = [[InlineKeyboardButton("🔄 تحديث", callback_data=f"console|{folder}"), InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]
        await query.edit_message_text(f"🖥 *كونسول السيرفر*\n```\n{logs}\n```", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await query.edit_message_text("❌ فشل جلب الكونسول")

async def show_errors(update: Update, context: ContextTypes.DEFAULT_TYPE, folder: str):
    query = update.callback_query
    result = api_request("/api/bot/errors", params={"folder": folder}, api_key=context.user_data.get("api_key"))
    if result and result.get("success"):
        errors = result.get("errors", "✅ لا توجد أخطاء")
        if len(errors) > 3500: errors = "...\n" + errors[-3500:]
        keyboard = [[InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]
        await query.edit_message_text(f"⚠️ *سجل الأخطاء*\n```\n{errors}\n```", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await query.edit_message_text("❌ فشل جلب سجل الأخطاء")

async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    metrics = api_request("/api/system/metrics")
    cpu = metrics.get("cpu", "?") if metrics else "?"
    ram = metrics.get("memory", "?") if metrics else "?"
    disk = metrics.get("disk", "?") if metrics else "?"
    await query.edit_message_text(
        f"━━━━━━━━━━━━━━━━━━━━\n  📊 إحصائيات النظام\n━━━━━━━━━━━━━━━━━━━━\n🖥 CPU:  *{cpu}%*\n💾 RAM:  *{ram}%*\n💿 Disk: *{disk}%*",
        parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="admin_panel")]])
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data

    if data == "main_menu":
        await show_main_menu(update, context, edit=True)
    elif data == "my_servers":
        await show_servers_list(update, context)
    elif data in ("enter_api", "change_api"):
        context.user_data.pop("api_key", None)
        await query.edit_message_text("🔑 *أدخل API Key الخاص بك:*\n\nيمكنك الحصول عليه من لوحة التحكم في الموقع.", parse_mode="Markdown")
        return WAITING_FOR_API_KEY
    elif data == "logout":
        context.user_data.clear()
        await query.edit_message_text("🚪 تم تسجيل الخروج.\nاستخدم /start للدخول مجدداً.")
    elif data == "create_server":
        await query.edit_message_text("➕ *إنشاء سيرفر جديد*\n\n📝 أرسل اسم السيرفر:", parse_mode="Markdown")
        return WAITING_FOR_NEW_SERVER_NAME
    elif data == "admin_panel":
        await show_admin_panel(update, context)
    elif data == "admin_stats":
        await admin_stats(update, context)

    elif "|" in data:
        cmd, value = data.split("|", 1)
        api_key = context.user_data.get("api_key")

        if cmd in ("srv_start", "srv_stop", "srv_restart", "srv_delete"):
            action = cmd.replace("srv_", "")
            result = api_request("/api/bot/server/action", method="POST", data={"api_key": api_key, "folder": value, "action": action})
            if result and result.get("success"):
                await query.answer(result.get("message", "✅ تم")[:200], show_alert=True)
            else:
                await query.answer(f"❌ {result.get('message', 'فشل')}"[:200], show_alert=True)
            await show_servers_list(update, context)
        elif cmd == "console":
            await show_console(update, context, value)
        elif cmd == "errors":
            await show_errors(update, context, value)
        elif cmd == "install":
            result = api_request("/api/bot/install", method="POST", data={"api_key": api_key, "folder": value})
            msg = result.get("message", "✅ جاري التثبيت") if result and result.get("success") else f"❌ {result.get('message', 'فشل')}"
            await query.edit_message_text(f"📦 *تثبيت المكتبات*\n\n{msg}\n\nتابع الكونسول للتفاصيل.", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🖥 كونسول", callback_data=f"console|{value}"), InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]))

    return ConversationHandler.END

def run_telegram_bot():
    try:
        print("\n" + "="*60)
        print(f" 🤖 ZIAD HOST - جاري تشغيل بوت التحكم المدمج")
        print(" 🚀 يتم الآن الاتصال بخوادم تليجرام...")
        print("="*60 + "\n")
        
        application = Application.builder().token(BOT_TOKEN).build()
        
        conv = ConversationHandler(
            entry_points=[
                CommandHandler("start", start),
                CommandHandler("help", help_command),
                CommandHandler("info", info_command),
                CallbackQueryHandler(button_callback),
            ],
            states={
                WAITING_FOR_API_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_api_key)],
                WAITING_FOR_NEW_SERVER_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_server_name)],
                WAITING_FOR_SERVER_TYPE: [CallbackQueryHandler(receive_server_type, pattern="^server_type_")],
            },
            fallbacks=[CommandHandler("start", start)],
            per_user=True, per_chat=True,
        )

        application.add_handler(conv)
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("info", info_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        application.add_error_handler(error_handler)
        
        print(" ✅ بوت ZIAD HOST جاهز الآن ويعمل بشكل مستمر!")
        print(" 📡 الحالة: نشط وينتظر التفاعلات...\n")
        
        application.run_polling(drop_pending_updates=True)
    except Exception as e:
        logger.error(f"❌ خطأ في تشغيل بوت تيليجرام: {str(e)}")

if __name__ == "__main__":
    threading.Thread(target=run_telegram_bot, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
