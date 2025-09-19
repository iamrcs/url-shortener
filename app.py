#!/usr/bin/env python3
import os
import re
import string
import random
import ipaddress
import logging
import threading
import time
import atexit
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# Optional GitHub backup helpers (keep guarded)
try:
    from backup_github import push_db_to_github, restore_db_from_github
except Exception:
    push_db_to_github = None
    restore_db_from_github = None

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# -----------------------------
# Attempt DB restore at startup (non-fatal)
# -----------------------------
if restore_db_from_github:
    try:
        logger.info("Attempting to restore DB from GitHub backup...")
        restore_db_from_github()
        logger.info("Restore complete (if backup existed).")
    except Exception as e:
        logger.warning("Failed to restore DB from GitHub: %s", e)

# -----------------------------
# Flask App & Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "200 per day;50 per hour")
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 5)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 10)),
        "pool_timeout": 30,
    }

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

CORS(app)

# Adjust DATABASE_URL for SQLAlchemy if needed
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(app)

# -----------------------------
# Redis client init (optional)
# -----------------------------
r = None
REDIS_URL = app.config.get("REDIS_URL")
if REDIS_URL:
    try:
        import redis as redislib
        r = redislib.from_url(REDIS_URL)
        r.ping()
        logger.info("Connected to Redis at %s", REDIS_URL)
    except Exception as e:
        logger.warning("Redis unavailable: %s", e)
        r = None

# -----------------------------
# Rate Limiter (use Redis if available)
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
    # Consider adding Content-Security-Policy in future
    return response

# -----------------------------
# Slug validation (lowercase stored)
# -----------------------------
slug_pattern = re.compile(r"^[a-z0-9_-]{3,50}$")  # expect lowercased input

# -----------------------------
# Database Model
# -----------------------------
class URLMap(db.Model):
    __tablename__ = "url_map"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False, index=True)
    clicks = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_clicked = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
def normalize_slug(s: str) -> str:
    if not s:
        return ""
    return s.strip().lower()

def generate_slug(length=6, attempts=50):
    chars = string.ascii_lowercase + string.digits  # keep lowercase to match DB
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length))
        if not slug_exists(slug):
            return slug
    # As a fallback, grow length and retry
    for _ in range(3):
        length += 1
        for _ in range(attempts):
            slug = "".join(random.choices(chars, k=length))
            if not slug_exists(slug):
                return slug
    raise Exception("Failed to generate unique slug after many attempts")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = (parsed.hostname or "").strip().lower()
        # reject explicit private IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            # not an IP
            pass

        # reject common private hostnames
        if hostname == "localhost":
            return False
        private_prefixes = ("10.", "192.168.",) + tuple(f"172.{i}." for i in range(16, 32))
        if any(hostname.startswith(p) for p in private_prefixes):
            return False

        return True
    except Exception:
        return False

def get_existing_by_url(url: str):
    """Return cached slug for this URL or lookup quickly in DB and cache it."""
    if not url:
        return None

    # Redis fast path
    if r:
        try:
            cached = r.get(f"url:{url}")
            if cached:
                return cached.decode()
        except Exception:
            logger.debug("Redis get error for url:%s", url, exc_info=True)

    # DB lookup: only select slug (cheaper)
    try:
        row = db.session.query(URLMap.slug).filter_by(long_url=url).first()
        if row:
            slug = row[0]
            if r:
                try:
                    pipe = r.pipeline()
                    pipe.setex(f"url:{url}", 3600 * 24 * 30, slug)
                    pipe.setex(f"slug:{slug}", 3600 * 24 * 30, url)
                    pipe.execute()
                except Exception:
                    logger.debug("Redis pipeline set error", exc_info=True)
            return slug
    except SQLAlchemyError:
        logger.exception("DB error in get_existing_by_url")
    return None

def slug_exists(slug: str) -> bool:
    if not slug:
        return False
    slug = slug.lower()
    try:
        return db.session.query(URLMap.id).filter_by(slug=slug).first() is not None
    except SQLAlchemyError:
        logger.exception("DB error in slug_exists")
        return False

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    ok = True
    details = {}
    # DB quick check
    try:
        db.session.execute("SELECT 1")
        details["db"] = "ok"
    except Exception as e:
        details["db"] = f"error: {e}"
        ok = False
    # Redis quick check
    if r:
        try:
            r.ping()
            details["redis"] = "ok"
        except Exception as e:
            details["redis"] = f"error: {e}"
            ok = False
    else:
        details["redis"] = "disabled"

    return jsonify({"ok": ok, "details": details})

@app.route("/shorten", methods=["POST"])
@limiter.limit("5/second")
def shorten():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    long_url = (data.get("url") or "").strip()
    custom_slug = normalize_slug(data.get("slug") or "")

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # Fast path: if URL already shortened (cache or DB), return early (unless custom slug provided)
    if not custom_slug:
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url.rstrip("/") + "/" + existing_slug,
                "msg": "URL already shortened"
            }), 200

    # Validate and handle custom slug
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        try:
            slug = generate_slug()
        except Exception as e:
            logger.exception("Slug generation failed")
            return jsonify({"ok": False, "error": "Could not generate slug"}), 500

    # Persist to DB
    new_entry = URLMap(slug=slug, long_url=long_url)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # race condition: slug was taken between check and commit
        return jsonify({"ok": False, "error": "Slug already taken"}), 409
    except Exception:
        db.session.rollback()
        logger.exception("DB error when inserting new short url")
        return jsonify({"ok": False, "error": "Internal error"}), 500

    # Populate Redis cache
    if r:
        try:
            pipe = r.pipeline()
            pipe.setex(f"url:{long_url}", 3600 * 24 * 30, slug)
            pipe.setex(f"slug:{slug}", 3600 * 24 * 30, long_url)
            pipe.setex(f"clicks:{slug}", 3600 * 24 * 30, 0)
            pipe.execute()
        except Exception:
            logger.debug("Redis setex pipeline failed on shorten", exc_info=True)

    return jsonify({
        "ok": True,
        "code": slug,
        "short_url": request.host_url.rstrip("/") + "/" + slug,
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

    # Try Redis first
    if r:
        try:
            cached = r.get(f"slug:{slug_l}")
            if cached:
                long_url = cached.decode()
        except Exception:
            logger.debug("Redis get error in redirect", exc_info=True)

    # DB fallback
    entry_id = None
    if not long_url:
        try:
            row = db.session.query(URLMap.id, URLMap.long_url).filter_by(slug=slug_l).first()
            if row:
                entry_id, long_url = row
                # cache it
                if r:
                    try:
                        pipe = r.pipeline()
                        pipe.setex(f"slug:{slug_l}", 3600 * 24 * 30, long_url)
                        pipe.setex(f"url:{long_url}", 3600 * 24 * 30, slug_l)
                        pipe.execute()
                    except Exception:
                        logger.debug("Redis pipeline error caching slug after DB fetch", exc_info=True)
        except SQLAlchemyError:
            logger.exception("DB error while fetching slug for redirect")

    if not long_url:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    # Always increment clicks (important: do this regardless of whether Redis was the source)
    try:
        # update by slug directly (single DB hit)
        db.session.query(URLMap).filter_by(slug=slug_l).update({
            URLMap.clicks: URLMap.clicks + 1,
            URLMap.last_clicked: datetime.now(timezone.utc)
        }, synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Failed to update clicks in DB for slug %s", slug_l)

    # Keep Redis clicks value in sync (best-effort)
    if r:
        try:
            # increment clicks key in redis if exists, else set to 1
            if r.exists(f"clicks:{slug_l}"):
                r.incr(f"clicks:{slug_l}")
            else:
                # read authoritative DB value
                try:
                    clicks_row = db.session.query(URLMap.clicks).filter_by(slug=slug_l).first()
                    clicks_val = clicks_row[0] if clicks_row else 1
                except Exception:
                    clicks_val = 1
                r.setex(f"clicks:{slug_l}", 3600 * 24 * 30, clicks_val)
        except Exception:
            logger.debug("Redis clicks sync failed", exc_info=True)

    # Permanent redirect
    return redirect(long_url, code=301)

@app.route("/api/stats/<slug>")
def stats(slug):
    if not slug:
        return jsonify({"ok": False, "error": "Slug not provided"}), 404

    slug_l = slug.lower()
    try:
        row = db.session.query(
            URLMap.slug, URLMap.long_url, URLMap.clicks, URLMap.created_at, URLMap.last_clicked
        ).filter_by(slug=slug_l).first()
    except SQLAlchemyError:
        logger.exception("DB error while fetching stats")
        return jsonify({"ok": False, "error": "Internal error"}), 500

    if not row:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    slug_val, long_url, clicks, created_at, last_clicked = row
    return jsonify({
        "ok": True,
        "slug": slug_val,
        "url": long_url,
        "clicks": int(clicks or 0),
        "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
        "last_clicked": last_clicked.isoformat() if isinstance(last_clicked, datetime) else None,
        "short_url": request.host_url.rstrip("/") + "/" + slug_val
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
    logger.exception("Server error: %s", e)
    return jsonify({"ok": False, "error": "Internal server error"}), 500

# -----------------------------
# Backup thread (runs daily at 23:59 UTC)
# -----------------------------
def seconds_until_next(target_hour=23, target_minute=59):
    now = datetime.now(timezone.utc)
    target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
    if now >= target:
        target += timedelta(days=1)
    return (target - now).total_seconds()

def daily_backup_thread():
    if not push_db_to_github:
        logger.info("push_db_to_github not available; daily backup thread will exit.")
        return
    while True:
        try:
            secs = seconds_until_next(23, 59)  # schedule at 23:59 UTC
            logger.info("Daily backup thread sleeping for %d seconds", int(secs))
            time.sleep(secs)
            try:
                logger.info("Running scheduled DB backup to GitHub...")
                push_db_to_github()
                logger.info("Scheduled DB backup succeeded.")
            except Exception as e:
                logger.exception("Scheduled DB backup failed: %s", e)
        except Exception:
            logger.exception("Unexpected error in daily_backup_thread; retrying in 60s")
            time.sleep(60)

# Start daily backup thread if push function exists
if push_db_to_github:
    t = threading.Thread(target=daily_backup_thread, daemon=True)
    t.start()

# Backup on shutdown (best-effort)
if push_db_to_github:
    def _atexit_push():
        try:
            logger.info("Running push_db_to_github on shutdown...")
            push_db_to_github()
            logger.info("Shutdown backup done.")
        except Exception:
            logger.exception("Shutdown backup failed.")
    atexit.register(_atexit_push)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # For production use gunicorn/uwsgi; the builtin server is fine for dev
    app.run(host="0.0.0.0", port=port, threaded=True)
