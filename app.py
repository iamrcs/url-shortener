#!/usr/bin/env python3
"""
Improved URL shortener app:
- safer slug generation (secrets)
- hashed Redis keys for long URLs
- increment clicks in Redis and batch-flush to DB via background thread (atomic rename)
- configurable flush interval & batching
- small validation/robustness improvements
"""
import os
import re
import string
import random
import secrets
import hashlib
import uuid
import logging
import threading
import time
import atexit
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict

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
    REDIS_URL = os.environ.get("REDIS_URL", "")  # empty disables Redis
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "200 per day;50 per hour")
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 5)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 10)),
        "pool_timeout": 30,
    }
    # Click flush tuning
    CLICK_FLUSH_INTERVAL = int(os.environ.get("CLICK_FLUSH_INTERVAL", 60))  # seconds
    CLICK_BATCH_MAX = int(os.environ.get("CLICK_BATCH_MAX", 500))          # max slugs per batch flush
    CLICK_KEY_PREFIX = os.environ.get("CLICK_KEY_PREFIX", "iiuo")          # namespace prefix

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

# Consider restricting CORS in production
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
        r = redislib.from_url(REDIS_URL, decode_responses=False)  # keep bytes for less surprises
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
# Helper utilities
# -----------------------------
def normalize_slug(s: Optional[str]) -> str:
    if not s:
        return ""
    return s.strip().lower()

def _long_url_hash_key(url: str) -> str:
    """Create a stable short hash for using in Redis keys rather than raw long URL."""
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"{app.config['CLICK_KEY_PREFIX']}:urlhash:{h}"

def _slug_clicks_hash() -> str:
    """Redis hash name for pending clicks"""
    return f"{app.config['CLICK_KEY_PREFIX']}:clicks_pending"

def _slug_last_clicked_hash() -> str:
    """Redis hash name for last clicked timestamps"""
    return f"{app.config['CLICK_KEY_PREFIX']}:last_clicked"

def generate_slug(length=6, attempts=50) -> str:
    """Generate a unique slug using secrets (cryptographically strong RNG)."""
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(attempts):
        slug = "".join(secrets.choice(alphabet) for _ in range(length))
        if not slug_exists(slug):
            return slug
    # fallback: try with increased length and a few attempts, with collision retry
    for extra in range(1, 4):
        length += 1
        for _ in range(attempts):
            slug = "".join(secrets.choice(alphabet) for _ in range(length))
            if not slug_exists(slug):
                return slug
    # last attempt: UUID-derived slug (short)
    slug = uuid.uuid4().hex[:length]
    if not slug_exists(slug):
        return slug
    raise Exception("Failed to generate unique slug after many attempts")

def is_valid_url(url: str, allow_fix_scheme: bool = True) -> bool:
    """Basic URL validation. Optionally auto-prepend https if no scheme given."""
    if not url:
        return False
    url = url.strip()
    if len(url) > 4096:  # protect against extremely long URLs
        return False

    # Add scheme if missing (useful for user convenience)
    if allow_fix_scheme and "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = (parsed.hostname or "").strip().lower()
        # reject explicit private IPs
        try:
            import ipaddress as _ip
            ip = _ip.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # not an IP, continue
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

# -----------------------------
# DB / Cache helpers
# -----------------------------
def get_existing_by_url(url: str) -> Optional[str]:
    """Return cached slug for this URL, or lookup in DB and cache it."""
    if not url:
        return None

    url_key = _long_url_hash_key(url)

    if r:
        try:
            cached = r.get(url_key)
            if cached:
                return cached.decode() if isinstance(cached, bytes) else cached
        except Exception:
            logger.debug("Redis get error for url:%s", url, exc_info=True)

    # DB lookup: select slug only
    try:
        row = db.session.query(URLMap.slug).filter_by(long_url=url).first()
        if row:
            slug = row[0]
            if r:
                try:
                    # cache mapping and clicks placeholder
                    pipe = r.pipeline()
                    pipe.setex(url_key, 3600 * 24 * 30, slug)
                    pipe.setex(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug}", 3600 * 24 * 30, url)
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
    long_url_raw = (data.get("url") or "").strip()
    custom_slug = normalize_slug(data.get("slug") or "")

    # Try to fix scheme if omitted
    long_url = long_url_raw if "://" in long_url_raw else ("https://" + long_url_raw if long_url_raw else "")

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
        except Exception:
            logger.exception("Slug generation failed")
            return jsonify({"ok": False, "error": "Could not generate slug"}), 500

    # Persist to DB
    new_entry = URLMap(slug=slug, long_url=long_url)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # race condition: slug was taken
        return jsonify({"ok": False, "error": "Slug already taken"}), 409
    except Exception:
        db.session.rollback()
        logger.exception("DB error when inserting new short url")
        return jsonify({"ok": False, "error": "Internal error"}), 500

    # Populate Redis cache
    if r:
        try:
            url_key = _long_url_hash_key(long_url)
            pipe = r.pipeline()
            pipe.setex(url_key, 3600 * 24 * 30, slug)
            pipe.setex(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug}", 3600 * 24 * 30, long_url)
            # keep a clicks key only for historical fallback
            pipe.setex(f"{app.config['CLICK_KEY_PREFIX']}:clicks:{slug}", 3600 * 24 * 30, 0)
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
            cached = r.get(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug_l}")
            if cached:
                long_url = cached.decode() if isinstance(cached, bytes) else cached
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
                        pipe.setex(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug_l}", 3600 * 24 * 30, long_url)
                        pipe.setex(_long_url_hash_key(long_url), 3600 * 24 * 30, slug_l)
                        pipe.execute()
                    except Exception:
                        logger.debug("Redis pipeline error caching slug after DB fetch", exc_info=True)
        except SQLAlchemyError:
            logger.exception("DB error while fetching slug for redirect")

    if not long_url:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    # Record click: prefer Redis increment (fast). DB updates are done by background flusher.
    now_ts = int(datetime.now(timezone.utc).timestamp())

    if r:
        try:
            # store pending clicks in a hash (slug -> count)
            r.hincrby(_slug_clicks_hash(), slug_l, 1)
            # store last clicked timestamp in a hash
            r.hset(_slug_last_clicked_hash(), slug_l, now_ts)
        except Exception:
            logger.debug("Redis click increment failed; falling back to DB update", exc_info=True)
            # fallback to immediate DB update (best-effort)
            try:
                db.session.query(URLMap).filter_by(slug=slug_l).update({
                    URLMap.clicks: URLMap.clicks + 1,
                    URLMap.last_clicked: datetime.now(timezone.utc)
                }, synchronize_session=False)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("Failed fallback DB clicks update for slug %s", slug_l)
    else:
        # No Redis: update DB synchronously (existing behavior)
        try:
            db.session.query(URLMap).filter_by(slug=slug_l).update({
                URLMap.clicks: URLMap.clicks + 1,
                URLMap.last_clicked: datetime.now(timezone.utc)
            }, synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to update clicks in DB for slug %s", slug_l)

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

    slug_val, long_url, clicks_db, created_at, last_clicked_db = row

    # If Redis exists, combine DB clicks with pending clicks
    clicks_pending = 0
    last_clicked_pending = None
    if r:
        try:
            pending = r.hget(_slug_clicks_hash(), slug_l)
            if pending:
                clicks_pending = int(pending.decode() if isinstance(pending, bytes) else pending)
            last_ts = r.hget(_slug_last_clicked_hash(), slug_l)
            if last_ts:
                last_clicked_pending = datetime.fromtimestamp(int(last_ts.decode() if isinstance(last_ts, bytes) else last_ts), tz=timezone.utc)
        except Exception:
            logger.debug("Redis stats read failed", exc_info=True)

    total_clicks = int(clicks_db or 0) + int(clicks_pending or 0)
    last_clicked = last_clicked_pending or last_clicked_db

    return jsonify({
        "ok": True,
        "slug": slug_val,
        "url": long_url,
        "clicks": total_clicks,
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
# Clicks flush thread (flush pending Redis clicks -> DB)
# Uses atomic rename trick so increments aren't lost while flushing.
# -----------------------------
def flush_pending_clicks_once(batch_max: int = 500):
    if not r:
        return

    pending_hash = _slug_clicks_hash()
    processing_hash = f"{pending_hash}:processing:{uuid.uuid4().hex}"

    try:
        # Atomically rename pending hash to a processing hash (if it exists).
        # If there is no pending hash, RENAME will raise a ResponseError. Use EXISTS to guard.
        if r.exists(pending_hash):
            r.rename(pending_hash, processing_hash)
        else:
            return

        # read all pending counts from processing_hash
        pending_map = r.hgetall(processing_hash) or {}
        if not pending_map:
            r.delete(processing_hash)
            return

        # limit the number of slugs processed in one flush to avoid large DB load
        items = list(pending_map.items())[:batch_max]

        # Build mapping slug -> count
        slug_counts: Dict[str, int] = {}
        for k, v in items:
            # redis returns bytes unless decode_responses=True
            slug = k.decode() if isinstance(k, bytes) else k
            cnt = int(v.decode() if isinstance(v, bytes) else v)
            slug_counts[slug] = cnt

        # Remove processed items from processing_hash to leave any unprocessed items (if len > batch_max)
        if len(items) < len(pending_map):
            # Only delete processed fields
            try:
                r.hdel(processing_hash, *[k for k, _ in items])
            except Exception:
                logger.debug("Failed hdel some fields from processing_hash", exc_info=True)
        else:
            r.delete(processing_hash)

        # Now apply batch updates in DB
        now = datetime.now(timezone.utc)
        for slug, add_count in slug_counts.items():
            try:
                # Use a single update per slug (increment and set last_clicked)
                db.session.query(URLMap).filter_by(slug=slug).update({
                    URLMap.clicks: URLMap.clicks + add_count,
                    URLMap.last_clicked: now
                }, synchronize_session=False)
            except Exception:
                db.session.rollback()
                logger.exception("Failed to apply clicks to DB for slug %s (count=%s)", slug, add_count)
        try:
            db.session.commit()
            logger.debug("Flushed %d slug(s) click(s) to DB", len(slug_counts))
        except Exception:
            db.session.rollback()
            logger.exception("Failed to commit flushed clicks")
    except Exception:
        logger.exception("Unexpected error during flush_pending_clicks_once")
        # In case of rename/processing issues, try to cleanup the processing hash to avoid stuck state
        try:
            if r.exists(processing_hash):
                # move it back (best-effort) to pending_hash so increments aren't lost
                # Using RENAMENX to avoid overwriting
                try:
                    # rename back only if pending_hash does not exist
                    r.renamenx(processing_hash, pending_hash)
                except Exception:
                    # as a last resort, ensure key exists and keep it
                    pass
        except Exception:
            logger.debug("Failed processing_hash cleanup", exc_info=True)

def clicks_flush_worker():
    """Background thread that periodically flushes pending clicks from Redis to DB."""
    if not r:
        logger.info("Redis not configured; clicks flush worker not started.")
        return

    interval = app.config.get("CLICK_FLUSH_INTERVAL", 60)
    batch_max = app.config.get("CLICK_BATCH_MAX", 500)
    logger.info("Clicks flush worker started: interval=%s sec, batch_max=%s", interval, batch_max)
    while True:
        try:
            time.sleep(interval)
            flush_pending_clicks_once(batch_max=batch_max)
        except Exception:
            logger.exception("Unexpected error in clicks_flush_worker; sleeping briefly and retrying")
            time.sleep(5)

# Start clicks flush worker if Redis available
if r:
    t_clicks = threading.Thread(target=clicks_flush_worker, daemon=True)
    t_clicks.start()

# -----------------------------
# Backup thread (runs daily at 23:59 UTC) - kept from original file
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
