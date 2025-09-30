#!/usr/bin/env python3
"""
Full Flask URL shortener app (app.py)

- Redis optional (fast click batching + cache)
- Click batching worker flushes to DB safely using app.app_context()
- Custom-slug duplicate message: "Direct slug already exists" (consistent)
- SQLite/Postgres via SQLAlchemy
- Rate limiting via flask-limiter (uses Redis if configured)
- Optional GitHub backup helpers (keep them guarded)
"""

import os
import re
import string
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
    CLICK_FLUSH_INTERVAL = int(os.environ.get("CLICK_FLUSH_INTERVAL", 60))  # seconds
    CLICK_BATCH_MAX = int(os.environ.get("CLICK_BATCH_MAX", 500))          # max slugs per flush
    CLICK_KEY_PREFIX = os.environ.get("CLICK_KEY_PREFIX", "iiuo")          # namespace prefix

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

# Consider restricting CORS in production
CORS(app)

# Adjust DATABASE_URL for SQLAlchemy if needed (Heroku style)
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
        # keep bytes for predictable behavior; decode explicitly where needed
        r = redislib.from_url(REDIS_URL, decode_responses=False)
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
def normalize_slug(s: Optional[str]) -> str:
    if not s:
        return ""
    return s.strip().lower()

def generate_slug(length=6, attempts=50) -> str:
    """Generate a unique slug using secrets (cryptographically strong RNG)."""
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(attempts):
        slug = "".join(secrets.choice(alphabet) for _ in range(length))
        if not slug_exists(slug):
            return slug
    for extra in range(1, 4):
        length += 1
        for _ in range(attempts):
            slug = "".join(secrets.choice(alphabet) for _ in range(length))
            if not slug_exists(slug):
                return slug
    # last attempt: uuid hex
    slug = uuid.uuid4().hex[:length]
    if not slug_exists(slug):
        return slug
    raise Exception("Failed to generate unique slug after many attempts")

def _long_url_hash_key(url: str) -> str:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"{app.config['CLICK_KEY_PREFIX']}:urlhash:{h}"

def _slug_clicks_hash() -> str:
    return f"{app.config['CLICK_KEY_PREFIX']}:clicks_pending"

def _slug_last_clicked_hash() -> str:
    return f"{app.config['CLICK_KEY_PREFIX']}:last_clicked"

def is_valid_url(url: str, allow_fix_scheme: bool = True) -> bool:
    if not url:
        return False
    url = url.strip()
    if len(url) > 4096:
        return False
    if allow_fix_scheme and "://" not in url:
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        hostname = (parsed.hostname or "").strip().lower()
        try:
            import ipaddress as _ip
            ip = _ip.ip_address(hostname)
            # reject private/loopback IPs
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # hostname might not be an IP, that's fine
            pass
        # reject localhost and common private ranges
        if hostname == "localhost":
            return False
        private_prefixes = ("10.", "192.168.",) + tuple(f"172.{i}." for i in range(16, 32))
        if any(hostname.startswith(p) for p in private_prefixes):
            return False
        return True
    except Exception:
        return False

def get_existing_by_url(url: str) -> Optional[str]:
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
    try:
        row = db.session.query(URLMap.slug).filter_by(long_url=url).first()
        if row:
            slug = row[0]
            if r:
                try:
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
    # If a template index.html exists it will be served; otherwise basic JSON for API-only use
    try:
        return render_template("index.html")
    except Exception:
        return jsonify({"ok": True, "msg": "URL Shortener API"}), 200

@app.route("/health")
def health():
    ok = True
    details = {}
    try:
        db.session.execute("SELECT 1")
        details["db"] = "ok"
    except Exception as e:
        details["db"] = f"error: {e}"
        ok = False
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

    long_url = long_url_raw if "://" in long_url_raw else ("https://" + long_url_raw if long_url_raw else "")

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # If user didn't provide a custom slug, try to return an existing short code for the same long URL
    if not custom_slug:
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url.rstrip("/") + "/" + existing_slug,
                "msg": "URL already shortened"
            }), 200

    if custom_slug:
        # Validate format
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        # Custom slug already exists -> return the requested message
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Direct slug already exists"}), 409
        slug = custom_slug
    else:
        try:
            slug = generate_slug()
        except Exception:
            logger.exception("Slug generation failed")
            return jsonify({"ok": False, "error": "Could not generate slug"}), 500

    new_entry = URLMap(slug=slug, long_url=long_url)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # Race condition / unique constraint — keep messaging consistent
        return jsonify({"ok": False, "error": "Direct slug already exists"}), 409
    except Exception:
        db.session.rollback()
        logger.exception("DB error when inserting new short url")
        return jsonify({"ok": False, "error": "Internal error"}), 500

    if r:
        try:
            url_key = _long_url_hash_key(long_url)
            pipe = r.pipeline()
            pipe.setex(url_key, 3600 * 24 * 30, slug)
            pipe.setex(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug}", 3600 * 24 * 30, long_url)
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
    # reuse same logic
    return shorten()

@app.route("/<slug>")
def redirect_slug(slug):
    if not slug:
        return jsonify({"ok": False, "error": "Slug not provided"}), 404

    slug_l = slug.lower()
    long_url = None

    if r:
        try:
            cached = r.get(f"{app.config['CLICK_KEY_PREFIX']}:slug:{slug_l}")
            if cached:
                long_url = cached.decode() if isinstance(cached, bytes) else cached
        except Exception:
            logger.debug("Redis get error in redirect", exc_info=True)

    entry_id = None
    if not long_url:
        try:
            row = db.session.query(URLMap.id, URLMap.long_url).filter_by(slug=slug_l).first()
            if row:
                # row is (id, long_url)
                entry_id, long_url = row
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

    now_ts = int(datetime.now(timezone.utc).timestamp())

    # Fast path: increment pending clicks in Redis
    if r:
        try:
            r.hincrby(_slug_clicks_hash(), slug_l, 1)
            r.hset(_slug_last_clicked_hash(), slug_l, now_ts)
        except Exception:
            # Fallback: update DB synchronously if Redis fails
            logger.debug("Redis click increment failed; falling back to DB update", exc_info=True)
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
        # No Redis: update DB directly
        try:
            db.session.query(URLMap).filter_by(slug=slug_l).update({
                URLMap.clicks: URLMap.clicks + 1,
                URLMap.last_clicked: datetime.now(timezone.utc)
            }, synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to update clicks in DB for slug %s", slug_l)

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
# Clicks flush functions (use app.app_context() for DB ops)
# -----------------------------
def flush_pending_clicks_once(batch_max: int = 500):
    """Atomically grab pending clicks hash and apply a batch to the DB."""
    if not r:
        return

    pending_hash = _slug_clicks_hash()
    processing_hash = f"{pending_hash}:processing:{uuid.uuid4().hex}"

    try:
        # If there are pending entries, move them to a processing key to avoid races
        if r.exists(pending_hash):
            # rename will fail if processing_hash exists; unique processing_hash avoids that
            r.rename(pending_hash, processing_hash)
        else:
            return

        pending_map = r.hgetall(processing_hash) or {}
        if not pending_map:
            r.delete(processing_hash)
            return

        items = list(pending_map.items())[:batch_max]

        slug_counts: Dict[str, int] = {}
        for k, v in items:
            slug = k.decode() if isinstance(k, bytes) else k
            cnt = int(v.decode() if isinstance(v, bytes) else v)
            slug_counts[slug] = cnt

        # If we processed only a subset, remove processed fields from the processing hash,
        # leaving the remainder for the next run (we used an ephemeral processing key to
        # avoid races with writers).
        if len(items) < len(pending_map):
            try:
                # delete only the keys we processed
                r.hdel(processing_hash, *[k for k, _ in items])
            except Exception:
                logger.debug("Failed hdel some fields from processing_hash", exc_info=True)
        else:
            # we processed all entries: safe to delete the processing key
            r.delete(processing_hash)

        now = datetime.now(timezone.utc)
        # Perform DB updates inside app context
        with app.app_context():
            try:
                for slug, add_count in slug_counts.items():
                    try:
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
            finally:
                try:
                    # remove/close the scoped session to avoid leaks in long-running thread
                    db.session.remove()
                except Exception:
                    logger.debug("db.session.remove() failed", exc_info=True)

    except Exception:
        logger.exception("Unexpected error during flush_pending_clicks_once")
        # Attempt best-effort recovery: if processing_hash still exists, try to rename back
        try:
            if r.exists(processing_hash):
                try:
                    # renamenx to avoid clobbering any new pending hash
                    r.renamenx(processing_hash, pending_hash)
                except Exception:
                    # if renamenx not available or fails, ignore (we don't want to raise here)
                    pass
        except Exception:
            logger.debug("Failed processing_hash cleanup", exc_info=True)

def clicks_flush_worker():
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
# Backup thread (daily) - uses push_db_to_github if available
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
            secs = seconds_until_next(23, 59)
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
    t_backup = threading.Thread(target=daily_backup_thread, daemon=True)
    t_backup.start()

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
