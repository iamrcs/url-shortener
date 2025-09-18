import os
import re
import string
import secrets
import json
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
from apscheduler.schedulers.background import BackgroundScheduler
from validators import url as validate_url

from backup_github import push_db_to_github, restore_db_from_github

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")]
)

# -----------------------------
# Flask App & Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATE_LIMIT_DEFAULT = "200 per day;50 per hour"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
CORS(app, resources={r"/*": {"origins": "*"}})

# Fix Postgres URL for SQLAlchemy
db_url = app.config["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_size": 5, "max_overflow": 10}
db = SQLAlchemy(app)

# -----------------------------
# Redis client with connection pooling
# -----------------------------
r = None
try:
    r = redis.from_url(app.config["REDIS_URL"], socket_timeout=2, decode_responses=True)
    r.ping()
    logging.info("Connected to Redis")
except Exception as e:
    logging.warning("Redis unavailable: %s", e)

# -----------------------------
# Rate Limiter
# -----------------------------
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=app.config["REDIS_URL"] if r else "memory://",
    app=app
)

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers.update({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'",
        'Cache-Control': 'no-store'
    })
    return response

# -----------------------------
# Slug validation
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")

# -----------------------------
# Database Model
# -----------------------------
class URLMap(db.Model):
    __tablename__ = "url_map"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False, index=True)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)

# -----------------------------
# Database Initialization
# -----------------------------
def init_db():
    """Initialize the database within an application context."""
    with app.app_context():
        db.create_all()
        logging.info("Database tables created")

# -----------------------------
# Restore DB on startup
# -----------------------------
def startup_tasks():
    """Perform startup tasks including DB restore and initialization."""
    with app.app_context():
        try:
            restore_db_from_github()
            logging.info("Database restored from GitHub")
        except Exception as e:
            logging.error("Failed to restore DB from GitHub: %s", e)
        init_db()

# Run startup tasks
startup_tasks()

# -----------------------------
# Helpers
# -----------------------------
def generate_slug(length: int = 6, attempts: int = 20) -> str:
    """Generate a unique, cryptographically secure slug."""
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(secrets.choice(chars) for _ in range(length))
        if not URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first():
            return slug
    raise ValueError("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    """Validate URL using validators library and additional checks."""
    if not validate_url(url):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    hostname = parsed.hostname or ""
    if hostname == "localhost" or any(hostname.startswith(p) for p in (
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31."
    )):
        return False
    return True

def get_existing_by_url(url: str) -> str | None:
    """Check if URL exists in cache or database."""
    if r:
        cached_slug = r.get(f"url:{url}")
        if cached_slug:
            return cached_slug
    entry = URLMap.query.filter_by(long_url=url).first()
    if entry and r:
        r.set(f"url:{url}", entry.slug, ex=30*24*3600)
    return entry.slug if entry else None

def slug_exists(slug: str) -> bool:
    """Check if slug exists in database."""
    return bool(URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first())

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("5/second")
def shorten():
    """Shorten a URL with optional custom slug and expiry."""
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    long_url = (data.get("url") or "").strip()
    custom_slug = (data.get("slug") or "").strip()
    expiry_days = data.get("expiry_days")

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL", "code": "INVALID_URL"}), 400

    if not custom_slug:
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url + existing_slug,
                "msg": "URL already shortened"
            }), 200

    slug = custom_slug or generate_slug()
    if custom_slug and not slug_pattern.match(custom_slug):
        return jsonify({"ok": False, "error": "Invalid slug format", "code": "INVALID_SLUG"}), 400
    if custom_slug and slug_exists(custom_slug):
        return jsonify({"ok": False, "error": "Slug already taken", "code": "SLUG_TAKEN"}), 409

    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if not 0 < days <= 3650:
                raise ValueError
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value", "code": "INVALID_EXPIRY"}), 400

    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"ok": False, "error": "Slug already taken", "code": "SLUG_TAKEN"}), 409

    if r:
        try:
            r.set(f"url:{long_url}", slug, ex=30*24*3600)
            r.set(f"slug:{slug}", long_url, ex=30*24*3600)
        except Exception as e:
            logging.warning("Failed to cache URL/slug: %s", e)

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
def redirect_slug(slug: str):
    """Redirect to the long URL for a given slug."""
    long_url = None
    if r:
        long_url = r.get(f"slug:{slug}")
        if long_url and r.exists(f"expired:{slug}"):
            return jsonify({"ok": False, "error": "Link expired", "code": "LINK_EXPIRED"}), 410

    entry = None
    if not long_url:
        entry = URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first()
        if entry:
            long_url = entry.long_url
            if r:
                r.set(f"slug:{slug}", long_url, ex=30*24*3600)

    if entry and entry.expires_at and entry.expires_at < datetime.now(timezone.utc):
        if r:
            r.set(f"expired:{slug}", "1", ex=3600)
        return jsonify({"ok": False, "error": "Link expired", "code": "LINK_EXPIRED"}), 410

    if long_url:
        if entry:
            entry.clicks += 1
            entry.last_clicked = datetime.now(timezone.utc)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logging.warning("Failed to update clicks: %s", e)
        return redirect(long_url, code=301)

    return jsonify({"ok": False, "error": "Slug not found", "code": "SLUG_NOT_FOUND"}), 404

@app.route("/api/stats/<slug>")
@limiter.limit("10/second")
def stats(slug: str):
    """Retrieve statistics for a given slug."""
    if r:
        cached_stats = r.get(f"stats:{slug}")
        if cached_stats:
            return jsonify(json.loads(cached_stats)), 200

    entry = URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first()
    if not entry:
        return jsonify({"ok": False, "error": "Slug not found", "code": "SLUG_NOT_FOUND"}), 404

    stats_data = {
        "ok": True,
        "slug": entry.slug,
        "url": entry.long_url,
        "clicks": entry.clicks,
        "created_at": entry.created_at.isoformat(),
        "last_clicked": entry.last_clicked.isoformat() if entry.last_clicked else None,
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        "short_url": request.host_url + entry.slug
    }
    if r:
        r.set(f"stats:{slug}", json.dumps(stats_data), ex=3600)
    return jsonify(stats_data), 200

@app.route("/cleanup", methods=["POST"])
def cleanup():
    """Remove expired URLs in batches."""
    batch_size = 1000
    deleted = 0
    while True:
        batch = URLMap.query.filter(URLMap.expires_at < datetime.now(timezone.utc)).limit(batch_size).all()
        if not batch:
            break
        for entry in batch:
            db.session.delete(entry)
        db.session.commit()
        deleted += len(batch)
    return jsonify({"ok": True, "deleted": deleted, "msg": "Expired URLs removed"}), 200

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Endpoint not found", "code": "NOT_FOUND"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please wait.", "code": "RATE_LIMIT_EXCEEDED"}), 429

@app.errorhandler(500)
def server_error(e):
    logging.exception("Server error: %s", e)
    return jsonify({"ok": False, "error": "Internal server error", "code": "INTERNAL_ERROR"}), 500

# -----------------------------
# Auto backup with APScheduler
# -----------------------------
scheduler = BackgroundScheduler()
scheduler.add_job(push_db_to_github, "cron", hour=23, minute=59)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
