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
from collections import deque

from backup_github import push_db_to_github, restore_db_from_github

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------
# Restore DB from GitHub (startup)
# -----------------------------
try:
    restore_db_from_github()
    logging.info("restore_db_from_github: success")
except Exception as e:
    logging.warning("restore_db_from_github failed on startup: %s", e)

# -----------------------------
# Flask Config
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
    # Cache TTL for permanent entries (in seconds) - to prevent unbounded Redis growth
    REDIS_PERMANENT_TTL = int(os.environ.get("REDIS_PERMANENT_TTL", 60 * 60 * 24 * 30))  # 30 days

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
CORS(app)

# Fix Postgres URL if present
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
db = SQLAlchemy(app)

# -----------------------------
# Redis
# -----------------------------
REDIS_URL = app.config.get("REDIS_URL")
r = None
if REDIS_URL:
    try:
        # decode_responses=True to always get strings from redis
        r = redis.from_url(REDIS_URL, decode_responses=True)
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
    # HSTS, frame, content sniffing
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# -----------------------------
# Slug Validation
# -----------------------------
# allow 2-50 chars, letters, digits, -, _
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{2,50}$")

# -----------------------------
# DB Model
# -----------------------------
class URLMap(db.Model):
    __tablename__ = "url_map"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False, index=True)
    clicks = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_expiry = db.Column(db.Boolean, default=False, nullable=False)

    def to_dict(self, host_url=""):
        return {
            "slug": self.slug,
            "url": self.long_url,
            "clicks": int(self.clicks),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_clicked": self.last_clicked.isoformat() if self.last_clicked else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "short_url": (host_url + self.slug) if host_url else None,
            "is_expiry": self.is_expiry
        }

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
def now_utc():
    return datetime.now(timezone.utc)

def normalize_slug(slug: str) -> str:
    return (slug or "").strip()

def normalize_url(url: str) -> str:
    return (url or "").strip()

def generate_slug(length=6, attempts=50):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length)).strip()
        # check redis first for quick rejection
        if r:
            try:
                if r.exists(f"slug:{slug}"):
                    continue
            except Exception:
                pass
        # check DB (case-insensitive)
        exists = db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug.lower()).first()
        if not exists:
            return slug
    raise Exception("Failed to generate unique slug after attempts")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        hostname = parsed.hostname or ""
        # prevent private IP ranges and loopback
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # hostname not IP - ok
            pass
        private_prefixes = (
            "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31."
        )
        if hostname == "localhost" or any(hostname.startswith(p) for p in private_prefixes):
            return False
        return True
    except Exception:
        return False

def get_existing_by_url(url: str):
    """
    Return existing slug for a permanent long_url (is_expiry == False).
    Uses Redis cache first, then DB.
    """
    url = normalize_url(url)
    if r:
        try:
            cached = r.get(f"url:{url}")
            if cached:
                return cached  # decode_responses=True so it's already a str
        except Exception:
            pass
    row = db.session.query(URLMap.slug).filter(URLMap.long_url == url, URLMap.is_expiry == False).first()
    if row:
        slug = row[0]
        if r:
            try:
                # cache for some time
                with r.pipeline() as pipe:
                    pipe.set(f"url:{url}", slug, ex=app.config['REDIS_PERMANENT_TTL'])
                    pipe.set(f"slug:{slug}", url, ex=app.config['REDIS_PERMANENT_TTL'])
                    pipe.hset(f"stats:{slug}", mapping={"clicks": "0", "created_at": now_utc().isoformat()})
                    pipe.execute()
            except Exception:
                pass
        return slug
    return None

def slug_exists(slug: str) -> bool:
    slug = normalize_slug(slug)
    if not slug:
        return False
    if r:
        try:
            if r.exists(f"slug:{slug}"):
                return True
        except Exception:
            pass
    # case-insensitive check in DB
    return db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug.lower()).first() is not None

# -----------------------------
# Click update queue (deque + batching)
# -----------------------------
click_update_queue = deque()
click_queue_lock = threading.Lock()
CLICK_BATCH_SIZE = 50
CLICK_BATCH_WAIT = 0.2  # seconds to wait to allow batching

def click_update_worker():
    while True:
        batch = []
        # collect up to CLICK_BATCH_SIZE items
        with click_queue_lock:
            while click_update_queue and len(batch) < CLICK_BATCH_SIZE:
                batch.append(click_update_queue.popleft())
        if not batch:
            time.sleep(0.1)
            continue
        try:
            with app.app_context():
                # Build mapping slug -> latest click_time and count
                updates = {}
                for slug, click_time in batch:
                    if slug not in updates:
                        updates[slug] = {"count": 0, "last_clicked": click_time}
                    updates[slug]["count"] += 1
                    # keep latest timestamp
                    if click_time and (updates[slug]["last_clicked"] is None or click_time > updates[slug]["last_clicked"]):
                        updates[slug]["last_clicked"] = click_time

                for slug, info in updates.items():
                    entry = db.session.query(URLMap).filter(URLMap.slug == slug).first()
                    if entry:
                        entry.clicks = (entry.clicks or 0) + info["count"]
                        entry.last_clicked = info["last_clicked"]
                        db.session.add(entry)
                        # update Redis stats / keys
                        if r:
                            try:
                                ttl = None
                                if entry.expires_at:
                                    ttl = int((entry.expires_at - now_utc()).total_seconds())
                                    if ttl < 0:
                                        ttl = 0
                                # hset stats
                                with r.pipeline() as pipe:
                                    pipe.hset(f"stats:{slug}", mapping={
                                        "clicks": str(entry.clicks),
                                        "last_clicked": entry.last_clicked.isoformat() if entry.last_clicked else "",
                                        "expires_at": "" if not entry.expires_at else entry.expires_at.isoformat(),
                                        "long_url": entry.long_url,
                                        "created_at": entry.created_at.isoformat() if entry.created_at else ""
                                    })
                                    if ttl and ttl > 0:
                                        pipe.set(f"slug:{slug}", entry.long_url, ex=ttl)
                                        pipe.set(f"url:{entry.long_url}", slug, ex=ttl)
                                    else:
                                        # fallback: set bounded TTL for permanent links
                                        pipe.set(f"slug:{slug}", entry.long_url, ex=app.config['REDIS_PERMANENT_TTL'])
                                        pipe.set(f"url:{entry.long_url}", slug, ex=app.config['REDIS_PERMANENT_TTL'])
                                    pipe.execute()
                            except Exception as e:
                                logging.debug("Failed to update redis stats for %s: %s", slug, e)
                db.session.commit()
        except Exception as e:
            logging.exception("Failed async click batch update: %s", e)
            try:
                db.session.rollback()
            except Exception:
                pass

# start click updater thread
threading.Thread(target=click_update_worker, daemon=True).start()

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
    long_url = normalize_url(data.get("url") or "")
    custom_slug = normalize_slug(data.get("slug") or "")
    # expiry can be provided as days (expiry_days) or seconds (expiry_seconds)
    expiry_days = data.get("expiry_days")
    expiry_seconds = data.get("expiry_seconds")
    expiry_minutes = data.get("expiry_minutes")

    if not long_url or not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # determine expiry
    expires_at = None
    is_expiry = False
    try:
        if expiry_seconds:
            secs = int(expiry_seconds)
            if secs <= 0 or secs > 60 * 60 * 24 * 365 * 10:  # limit up to 10 years in seconds
                return jsonify({"ok": False, "error": "Expiry seconds out of range"}), 400
            expires_at = now_utc() + timedelta(seconds=secs)
            is_expiry = True
        elif expiry_minutes:
            mins = int(expiry_minutes)
            if mins <= 0 or mins > 60 * 24 * 365 * 10:
                return jsonify({"ok": False, "error": "Expiry minutes out of range"}), 400
            expires_at = now_utc() + timedelta(minutes=mins)
            is_expiry = True
        elif expiry_days:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = now_utc() + timedelta(days=days)
                is_expiry = True
            else:
                return jsonify({"ok": False, "error": "Expiry days out of range"}), 400
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    # Permanent URLs: reuse existing slug (only if not expiry)
    if not is_expiry:
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            logging.info("Reusing existing slug for permanent URL: %s -> %s", existing_slug, long_url)
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url + existing_slug,
                "msg": "URL already shortened"
            }), 200

    # Custom slug
    slug = None
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        # generate slug with retries
        attempts = 0
        while True:
            attempts += 1
            try:
                slug = generate_slug()
                break
            except Exception:
                if attempts >= 3:
                    return jsonify({"ok": False, "error": "Failed to generate unique slug"}), 500

    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at, is_expiry=is_expiry)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        # slug race (another process created same slug)
        db.session.rollback()
        logging.warning("IntegrityError on slug %s during creation - retrying", slug)
        # if custom slug, return conflict; otherwise retry generate+insert few times
        if custom_slug:
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        retry = 0
        success = False
        while retry < 3:
            retry += 1
            try:
                slug = generate_slug()
                new_entry.slug = slug
                db.session.add(new_entry)
                db.session.commit()
                success = True
                break
            except IntegrityError:
                db.session.rollback()
        if not success:
            return jsonify({"ok": False, "error": "Slug generation conflict"}), 500
    except Exception as e:
        db.session.rollback()
        logging.exception("DB error creating slug: %s", e)
        return jsonify({"ok": False, "error": "Database error"}), 500

    # Redis cache
    if r:
        try:
            ttl = None
            if expires_at:
                ttl = int((expires_at - now_utc()).total_seconds())
                if ttl < 0:
                    ttl = 0
            # for permanent entries, set bounded TTL to avoid unbounded growth
            if not ttl or ttl <= 0:
                ttl = app.config['REDIS_PERMANENT_TTL']
            with r.pipeline() as pipe:
                pipe.set(f"url:{long_url}", slug, ex=ttl)
                pipe.set(f"slug:{slug}", long_url, ex=ttl)
                pipe.hset(f"stats:{slug}", mapping={
                    "clicks": "0",
                    "created_at": new_entry.created_at.isoformat(),
                    "last_clicked": "",
                    "expires_at": "" if not expires_at else expires_at.isoformat(),
                    "long_url": long_url
                })
                if is_expiry:
                    pipe.sadd("expiry_slugs", slug)
                pipe.execute()
        except Exception:
            logging.debug("Redis pipeline failed during shorten")

    logging.info("Created short URL: slug=%s long_url=%s expires_at=%s is_expiry=%s", slug, long_url, expires_at, is_expiry)
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
    slug = normalize_slug(slug)
    if not slug:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    long_url = None
    # try redis
    if r:
        try:
            cached = r.get(f"slug:{slug}")
            if cached:
                long_url = cached
        except Exception:
            pass

    # fetch DB entry (always check DB so we can validate expiry)
    entry = db.session.query(URLMap).filter(URLMap.slug == slug).first()
    if not entry:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    if entry.expires_at and entry.expires_at < now_utc():
        return jsonify({"ok": False, "error": "Link expired"}), 410

    if not long_url:
        long_url = entry.long_url
        if r:
            try:
                ttl = None
                if entry.expires_at:
                    ttl = int((entry.expires_at - now_utc()).total_seconds())
                    if ttl < 0:
                        ttl = 0
                if not ttl or ttl <= 0:
                    ttl = app.config['REDIS_PERMANENT_TTL']
                with r.pipeline() as pipe:
                    pipe.set(f"slug:{entry.slug}", entry.long_url, ex=ttl)
                    pipe.set(f"url:{entry.long_url}", entry.slug, ex=ttl)
                    pipe.execute()
            except Exception:
                pass

    # Queue click update (thread-safe append)
    try:
        with click_queue_lock:
            click_update_queue.append((entry.slug, now_utc()))
    except Exception:
        # fallback: immediately update DB (rare)
        try:
            entry.clicks = (entry.clicks or 0) + 1
            entry.last_clicked = now_utc()
            db.session.add(entry)
            db.session.commit()
        except Exception:
            db.session.rollback()

    logging.info("Redirecting slug=%s to %s", slug, long_url)
    return redirect(long_url, code=301)

@app.route("/api/stats/<slug>")
def stats(slug):
    slug = normalize_slug(slug)
    if not slug:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    entry = db.session.query(URLMap).filter(URLMap.slug == slug).first()
    if not entry:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    data = entry.to_dict(host_url=request.host_url)
    return jsonify({"ok": True, **data}), 200

@app.route("/cleanup", methods=["POST"])
def cleanup():
    """
    Cleanup expired entries.
    - Removes expired entries known in Redis expiry set (fast path)
    - Also scans DB for any expired entries (fallback) and removes them.
    """
    deleted_count = 0
    try:
        # 1) Redis-based cleanup (if redis available)
        if r:
            try:
                expiry_slugs = r.smembers("expiry_slugs") or set()
                # smembers returns set of strings
                for slug in list(expiry_slugs):
                    entry = db.session.query(URLMap).filter(URLMap.slug == slug).first()
                    if entry and entry.expires_at and entry.expires_at < now_utc():
                        db.session.delete(entry)
                        deleted_count += 1
                        with r.pipeline() as pipe:
                            pipe.delete(f"slug:{slug}")
                            pipe.delete(f"stats:{slug}")
                            pipe.srem("expiry_slugs", slug)
                            pipe.execute()
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logging.exception("Cleanup failed during redis-based phase: %s", e)
        # 2) DB-based cleanup fallback for entries that might not be in Redis
        try:
            expired_entries = db.session.query(URLMap).filter(
                URLMap.is_expiry == True,
                URLMap.expires_at != None,
                URLMap.expires_at < now_utc()
            ).all()
            for entry in expired_entries:
                slug = entry.slug
                try:
                    db.session.delete(entry)
                    deleted_count += 1
                    if r:
                        with r.pipeline() as pipe:
                            pipe.delete(f"slug:{slug}")
                            pipe.delete(f"stats:{slug}")
                            pipe.srem("expiry_slugs", slug)
                            pipe.execute()
                except Exception:
                    logging.debug("Failed to remove redis keys for expired slug %s", slug)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.exception("Cleanup failed during db-based phase: %s", e)
            return jsonify({"ok": False, "error": "Cleanup failed"}), 500
    except Exception as e:
        logging.exception("Cleanup unexpected failure: %s", e)
        return jsonify({"ok": False, "error": "Cleanup failed"}), 500

    logging.info("Cleanup completed, deleted=%d", deleted_count)
    return jsonify({"ok": True, "deleted": deleted_count, "msg": "Expired URLs removed"}), 200

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Endpoint not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please slow down."}), 429

@app.errorhandler(500)
def server_error(e):
    logging.exception("Server error: %s", e)
    return jsonify({"ok": False, "error": "Internal server error"}), 500

# -----------------------------
# Backup Thread (every 6 hours + at startup/shutdown)
# -----------------------------
def backup_worker(interval_hours=6):
    interval = max(1, interval_hours) * 3600
    while True:
        try:
            push_db_to_github()
            logging.info("push_db_to_github executed by backup_worker")
        except Exception as e:
            logging.error("Failed to push DB backup: %s", e)
        time.sleep(interval)

# start backup thread
threading.Thread(target=backup_worker, kwargs={"interval_hours": 6}, daemon=True).start()

# -----------------------------
# Shutdown Backup
# -----------------------------
def safe_push():
    try:
        push_db_to_github()
        logging.info("push_db_to_github executed at shutdown")
    except Exception as e:
        logging.warning("push_db_to_github at shutdown failed: %s", e)

atexit.register(safe_push)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info("Starting app on port %s", port)
    app.run(host="0.0.0.0", port=port, threaded=True)
