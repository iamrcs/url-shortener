import os
import re
import string
import random
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
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
    # Engine tuning to improve connection reuse & reduce overhead
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 5)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 10)),
        "pool_timeout": 30,
    }

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
CORS(app)

# Fix Postgres URL for SQLAlchemy (if present)
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
        r = None

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
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
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
    # store slug in lowercase for fast equality checks (avoid LOWER(...) in queries)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False, index=True)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_clicked = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers (kept simple & fast)
# -----------------------------
def generate_slug(length=6, attempts=20):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length)).lower()
        # use fast equality (slug is normalized to lowercase in DB)
        if not URLMap.query.filter_by(slug=slug).first():
            return slug
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = (parsed.hostname or "").strip()
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            # not an IP address — continue checks
            pass

        # keep prefix list compact
        private_prefixes = ("10.", "192.168.",) + tuple(f"172.{i}." for i in range(16, 32))
        if hostname == "localhost" or any(hostname.startswith(p) for p in private_prefixes):
            return False

        return True
    except Exception:
        return False

def get_existing_by_url(url: str):
    """Return cached slug for this URL or lookup quickly in DB and cache it."""
    if not url:
        return None

    # Try Redis first (fast path)
    if r:
        try:
            cached = r.get(f"url:{url}")
            if cached:
                return cached.decode()
        except Exception:
            pass

    # DB lookup: only select slug (cheaper than fetching whole object)
    row = db.session.query(URLMap.slug).filter_by(long_url=url).first()
    if row:
        slug = row[0]
        if r:
            try:
                # set both url->slug and slug->url in one pipeline
                pipe = r.pipeline()
                pipe.setex(f"url:{url}", 3600 * 24 * 30, slug)
                pipe.setex(f"slug:{slug}", 3600 * 24 * 30, url)
                pipe.execute()
            except Exception:
                pass
        return slug
    return None

def slug_exists(slug: str) -> bool:
    if not slug:
        return False
    slug = slug.lower()
    # fast equality check (uses index)
    return db.session.query(URLMap.id).filter_by(slug=slug).first() is not None

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

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # Normalize slug to lowercase to enable fast DB equality checks
    if custom_slug:
        custom_slug = custom_slug.lower()

    # Fast path: if URL already shortened (cache or DB), return early
    if not custom_slug:
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url + existing_slug,
                "msg": "URL already shortened"
            }), 200

    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        # generate already lowercased slugs
        slug = generate_slug()

    # store lowercased slug in DB (fast subsequent lookups)
    new_entry = URLMap(slug=slug, long_url=long_url)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # rare race: slug was taken between check and commit
        return jsonify({"ok": False, "error": "Slug already taken"}), 409

    # populate Redis cache (use pipeline for speed)
    if r:
        try:
            pipe = r.pipeline()
            pipe.setex(f"url:{long_url}", 3600 * 24 * 30, slug)
            pipe.setex(f"slug:{slug}", 3600 * 24 * 30, long_url)
            pipe.execute()
        except Exception:
            pass

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
    if not slug:
        return jsonify({"ok": False, "error": "Slug not provided"}), 404

    slug_l = slug.lower()
    long_url = None

    # Fast path: try Redis
    if r:
        try:
            cached = r.get(f"slug:{slug_l}")
            if cached:
                long_url = cached.decode()
        except Exception:
            pass

    # DB fallback: only fetch long_url and id (low overhead)
    entry_obj = None
    if not long_url:
        row = db.session.query(URLMap.id, URLMap.long_url).filter_by(slug=slug_l).first()
        if row:
            entry_id, long_url = row
            # cache result to Redis asynchronously (fast pipeline)
            if r:
                try:
                    r.setex(f"slug:{slug_l}", 3600 * 24 * 30, long_url)
                    r.setex(f"url:{long_url}", 3600 * 24 * 30, slug_l)
                except Exception:
                    pass

            # perform an efficient UPDATE: increment clicks + set last_clicked in one DB hit
            try:
                # Use query.update to avoid loading the full ORM object
                db.session.query(URLMap).filter_by(id=entry_id).update({
                    URLMap.clicks: URLMap.clicks + 1,
                    URLMap.last_clicked: datetime.now(timezone.utc)
                }, synchronize_session=False)
                db.session.commit()
            except Exception:
                db.session.rollback()

    if not long_url:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    # Permanent redirect (fast)
    return redirect(long_url, code=301)

@app.route("/api/stats/<slug>")
def stats(slug):
    if not slug:
        return jsonify({"ok": False, "error": "Slug not provided"}), 404

    slug_l = slug.lower()
    # fetch only required columns (lighter query)
    row = db.session.query(
        URLMap.slug, URLMap.long_url, URLMap.clicks, URLMap.created_at, URLMap.last_clicked
    ).filter_by(slug=slug_l).first()

    if not row:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    slug_val, long_url, clicks, created_at, last_clicked = row
    return jsonify({
        "ok": True,
        "slug": slug_val,
        "url": long_url,
        "clicks": clicks,
        "created_at": created_at.isoformat(),
        "last_clicked": last_clicked.isoformat() if last_clicked else None,
        "short_url": request.host_url + slug_val
    }), 200

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
# Auto backup thread at 23:59 daily
# -----------------------------
def daily_backup_thread():
    while True:
        now = datetime.now()
        target = now.replace(hour=23, minute=59, second=0, microsecond=0)
        if now >= target:
            target += timedelta(days=1)
        time.sleep((target - now).total_seconds())
        try:
            push_db_to_github()
        except Exception as e:
            logging.error("Failed to push DB backup: %s", e)

threading.Thread(target=daily_backup_thread, daemon=True).start()

# -----------------------------
# Backup on shutdown
# -----------------------------
atexit.register(push_db_to_github)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # production servers (gunicorn/uwsgi) are recommended; the built-in server is kept for dev
    app.run(host="0.0.0.0", port=port, threaded=True)
