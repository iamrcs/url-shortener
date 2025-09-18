import os
import re
import string
import random
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
import logging
import redis
import atexit
import threading
import time

from backup_github import push_db_to_github, restore_db_from_github

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Restore DB from GitHub on startup
# -----------------------------
restore_db_from_github()

# -----------------------------
# Flask App & Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATE_LIMIT_DEFAULT = "200 per day;50 per hour"
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_size": 10,
        "max_overflow": 20,
    }

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
CORS(app)

# Fix Postgres URL for SQLAlchemy
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
db = SQLAlchemy(app)

# -----------------------------
# Redis client
# -----------------------------
REDIS_URL = app.config.get("REDIS_URL")
r = None
if REDIS_URL:
    try:
        r = redis.from_url(REDIS_URL)
        r.ping()
        logging.info("Connected to Redis")
    except Exception as e:
        logging.warning("Redis unavailable: %s", e)

# -----------------------------
# Rate Limiter
# -----------------------------
storage_uri = REDIS_URL if r else "memory://"
limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri, app=app)

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# -----------------------------
# Slug validation
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")

# -----------------------------
# Database Model
# -----------------------------
class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False, index=True)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Cache Helpers
# -----------------------------
CACHE_EXPIRY = 3600 * 24 * 90  # 90 days

def cache_slug_url(slug, url):
    if r:
        try:
            with r.pipeline() as pipe:
                pipe.set(f"url:{url}", slug, ex=CACHE_EXPIRY)
                pipe.set(f"slug:{slug}", url, ex=CACHE_EXPIRY)
                pipe.execute()
        except:
            pass

def get_url_from_slug(slug):
    if r:
        cached = r.get(f"slug:{slug}")
        if cached:
            return cached.decode()
    return None

def get_slug_from_url(url):
    if r:
        cached = r.get(f"url:{url}")
        if cached:
            return cached.decode()
    return None

def slug_exists(slug: str) -> bool:
    return db.session.query(URLMap.id).filter_by(slug=slug).first() is not None

# -----------------------------
# Helpers
# -----------------------------
def generate_slug(length=6, attempts=20):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length))
        if not get_url_from_slug(slug) and not db.session.query(
            URLMap.id
        ).filter_by(slug=slug).first():
            return slug
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = parsed.hostname or ""
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            pass

        private_prefixes = (
            "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31."
        )
        if hostname == "localhost" or hostname.startswith(private_prefixes):
            return False

        return True
    except Exception:
        return False

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("5/second")
def shorten():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    long_url = (data.get("url") or "").strip()
    custom_slug = (data.get("slug") or "").strip()
    expiry_days = data.get("expiry_days")

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    if not custom_slug:
        cached_slug = get_slug_from_url(long_url)
        if cached_slug:
            return jsonify({
                "ok": True,
                "code": cached_slug,
                "short_url": request.host_url + cached_slug,
                "msg": "URL already shortened (cache)"
            }), 200

    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        slug = generate_slug()

    expires_at = None
    if expiry_days not in (None, ""):
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"ok": False, "error": "Slug already taken"}), 409

    cache_slug_url(slug, long_url)

    return jsonify({
        "ok": True,
        "code": slug,
        "short_url": request.host_url + slug,
        "msg": "URL shortened successfully!"
    }), 201

@app.route("/api/shorten", methods=["POST"])
@limiter.limit("5/second")
def api_shorten():
    return shorten()

@app.route("/<slug>")
def redirect_slug(slug):
    long_url = get_url_from_slug(slug)

    entry = None
    if not long_url:
        entry = db.session.query(URLMap).filter_by(slug=slug).first()
        if entry:
            long_url = entry.long_url
            cache_slug_url(slug, long_url)

    if entry and entry.expires_at and entry.expires_at < datetime.now(timezone.utc):
        return jsonify({"ok": False, "error": "Link expired"}), 410

    if long_url:
        if r:
            r.incr(f"clicks:{slug}")
        else:
            if entry:
                entry.clicks += 1
                entry.last_clicked = datetime.now(timezone.utc)
                db.session.commit()
        return redirect(long_url, code=301)

    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/api/stats/<slug>")
def stats(slug):
    entry = db.session.query(URLMap).filter_by(slug=slug).first()
    if entry:
        # merge Redis clicks
        redis_clicks = int(r.get(f"clicks:{slug}") or 0) if r else 0
        return jsonify({
            "ok": True,
            "slug": entry.slug,
            "url": entry.long_url,
            "clicks": entry.clicks + redis_clicks,
            "created_at": entry.created_at.isoformat(),
            "last_clicked": entry.last_clicked.isoformat() if entry.last_clicked else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "short_url": request.host_url + entry.slug
        }), 200
    return jsonify({"ok": False, "error": "Slug not found"}), 404

# -----------------------------
# Background Tasks
# -----------------------------
def flush_clicks_to_db():
    """Periodically flush Redis click counters to DB."""
    while True:
        if r:
            try:
                keys = r.keys("clicks:*")
                for key in keys:
                    slug = key.decode().split(":", 1)[1]
                    count = int(r.get(key) or 0)
                    if count > 0:
                        entry = db.session.query(URLMap).filter_by(slug=slug).first()
                        if entry:
                            entry.clicks += count
                            entry.last_clicked = datetime.now(timezone.utc)
                            db.session.commit()
                        r.delete(key)
            except Exception as e:
                logging.error("Failed to flush clicks: %s", e)
        time.sleep(60)  # flush every 60s

def daily_backup_thread():
    """Backup DB daily at 23:59"""
    while True:
        now = datetime.now()
        target = now.replace(hour=23, minute=59, second=0, microsecond=0)
        if now > target:
            target += timedelta(days=1)
        sleep_seconds = (target - now).total_seconds()
        time.sleep(sleep_seconds)
        try:
            push_db_to_github()
        except Exception as e:
            logging.error("Failed to push DB backup: %s", e)

# start background threads
threading.Thread(target=flush_clicks_to_db, daemon=True).start()
threading.Thread(target=daily_backup_thread, daemon=True).start()

# -----------------------------
# Backup on shutdown
# -----------------------------
atexit.register(push_db_to_github)

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Endpoint not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please wait."}), 429

@app.errorhandler(500)
def server_error(e):
    logging.exception("Server error: %s", e)
    return jsonify({"ok": False, "error": "Internal server error"}), 500

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
