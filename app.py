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

# local module: make sure push_db_to_github, restore_db_from_github exist
from backup_github import push_db_to_github, restore_db_from_github

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Restore DB from GitHub on startup (best-effort)
# -----------------------------
try:
    restore_db_from_github()
except Exception as e:
    logging.warning("restore_db_from_github failed on startup: %s", e)

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

# Fix Postgres URL for SQLAlchemy if needed
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(app)

# -----------------------------
# Redis client (optional)
# -----------------------------
REDIS_URL = app.config.get("REDIS_URL")
r = None
if REDIS_URL:
    try:
        r = redis.from_url(REDIS_URL, decode_responses=False)  # keep bytes, decode explicitly where needed
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
# Security Headers (NO Cache-Control here per request)
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Intentionally not setting Cache-Control as requested
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
    clicks = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, host_url=""):
        return {
            "slug": self.slug,
            "url": self.long_url,
            "clicks": int(self.clicks),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_clicked": self.last_clicked.isoformat() if self.last_clicked else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "short_url": (host_url + self.slug) if host_url else None,
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

def generate_slug(length=6, attempts=30):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length))
        slug_norm = slug.strip()
        # quick Redis check
        try:
            if r and r.exists(f"slug:{slug_norm}"):
                continue
        except Exception:
            pass
        # case-insensitive check in DB
        exists = db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug_norm.lower()).first()
        if not exists:
            return slug_norm
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = parsed.hostname or ""
        # if hostname is an IP, disallow private/loopback ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # not an IP — ok
            pass

        private_prefixes = (
            "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31."
        )
        if hostname == "localhost" or any(hostname.startswith(p) for p in private_prefixes):
            return False

        return True
    except Exception:
        return False

def get_existing_by_url(url: str):
    url = normalize_url(url)
    # Try Redis first
    if r:
        try:
            cached = r.get(f"url:{url}")
            if cached:
                # bytes -> str
                return cached.decode()
        except Exception:
            pass
    # Query DB (fast with index on long_url)
    row = db.session.query(URLMap.slug).filter(URLMap.long_url == url).first()
    if row:
        slug = row[0]
        if r:
            try:
                with r.pipeline() as pipe:
                    pipe.set(f"url:{url}", slug, ex=3600*24*30)
                    pipe.set(f"slug:{slug}", url, ex=3600*24*30)
                    # minimal stats cache
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
    # Check Redis quickly
    if r:
        try:
            if r.exists(f"slug:{slug}"):
                return True
        except Exception:
            pass
    # DB case-insensitive check
    return db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug.lower()).first() is not None

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
    expiry_days = data.get("expiry_days")

    if not long_url or not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # If custom slug provided: validate & uniqueness
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        # check existing mapping for same long_url
        existing_slug = get_existing_by_url(long_url)
        if existing_slug:
            return jsonify({
                "ok": True,
                "code": existing_slug,
                "short_url": request.host_url + existing_slug,
                "msg": "URL already shortened"
            }), 200
        slug = generate_slug()

    expires_at = None
    if expiry_days not in (None, ""):
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = now_utc() + timedelta(days=days)
            else:
                return jsonify({"ok": False, "error": "Expiry days out of range"}), 400
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    db.session.add(new_entry)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"ok": False, "error": "Slug already taken"}), 409
    except Exception as e:
        db.session.rollback()
        logging.exception("DB error creating slug: %s", e)
        return jsonify({"ok": False, "error": "Database error"}), 500

    # Populate Redis (both directions) and minimal stats
    if r:
        try:
            with r.pipeline() as pipe:
                pipe.set(f"url:{long_url}", slug, ex=3600*24*30)
                pipe.set(f"slug:{slug}", long_url, ex=3600*24*30)
                # store stats hash so lookup can be faster (kept in sync on click)
                pipe.hset(f"stats:{slug}", mapping={
                    "clicks": str(new_entry.clicks or 0),
                    "created_at": new_entry.created_at.isoformat(),
                    "last_clicked": "" if not new_entry.last_clicked else new_entry.last_clicked.isoformat(),
                    "expires_at": "" if not new_entry.expires_at else new_entry.expires_at.isoformat(),
                    "long_url": new_entry.long_url
                })
                pipe.execute()
        except Exception:
            logging.debug("Redis pipeline set failed during shorten")

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
    slug_lower = slug.lower()

    long_url = None
    entry = None

    # Try Redis for fast long_url lookup (but we'll still fetch DB to update stats reliably)
    if r:
        try:
            cached = r.get(f"slug:{slug}")
            if cached:
                long_url = cached.decode()
        except Exception:
            long_url = None

    # Always fetch DB entry (for stats/click updates and expiry checks)
    entry = db.session.query(URLMap).filter(db.func.lower(URLMap.slug) == slug_lower).first()

    if not entry:
        # No DB entry -> 404
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    # Check expiry
    if entry.expires_at and entry.expires_at < now_utc():
        return jsonify({"ok": False, "error": "Link expired"}), 410

    # Ensure long_url set from DB if Redis missed it
    if not long_url:
        long_url = entry.long_url
        # refresh Redis mapping
        if r:
            try:
                with r.pipeline() as pipe:
                    pipe.set(f"slug:{entry.slug}", entry.long_url, ex=3600*24*30)
                    pipe.set(f"url:{entry.long_url}", entry.slug, ex=3600*24*30)
                    pipe.execute()
            except Exception:
                pass

    # Update click counters and last_clicked timestamp (persist immediately)
    try:
        entry.clicks = (entry.clicks or 0) + 1
        entry.last_clicked = now_utc()
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.exception("Failed to update clicks for %s: %s", slug, e)

    # Update Redis stats mirror
    if r:
        try:
            with r.pipeline() as pipe:
                pipe.hset(f"stats:{entry.slug}", mapping={
                    "clicks": str(entry.clicks),
                    "last_clicked": "" if not entry.last_clicked else entry.last_clicked.isoformat(),
                    "expires_at": "" if not entry.expires_at else entry.expires_at.isoformat(),
                    "long_url": entry.long_url,
                    "created_at": entry.created_at.isoformat() if entry.created_at else ""
                })
                # refresh slug/url keys too
                pipe.set(f"slug:{entry.slug}", entry.long_url, ex=3600*24*30)
                pipe.set(f"url:{entry.long_url}", entry.slug, ex=3600*24*30)
                pipe.execute()
        except Exception:
            logging.debug("Redis pipeline set failed during redirect")

    # Permanent redirect as requested
    return redirect(long_url, code=301)

@app.route("/api/stats/<slug>")
def stats(slug):
    slug = normalize_slug(slug)
    if not slug:
        return jsonify({"ok": False, "error": "Slug not found"}), 404
    slug_lower = slug.lower()

    # Always prefer DB as source-of-truth for stats
    entry = db.session.query(URLMap).filter(db.func.lower(URLMap.slug) == slug_lower).first()
    if not entry:
        return jsonify({"ok": False, "error": "Slug not found"}), 404

    # Prepare response
    data = entry.to_dict(host_url=request.host_url)

    # Optionally include Redis mirror if available (for debug) but do not trust it
    return jsonify({"ok": True, **data}), 200

@app.route("/cleanup", methods=["POST"])
def cleanup():
    # Find slugs to delete (expired ones)
    expired_q = URLMap.query.filter(URLMap.expires_at != None, URLMap.expires_at < now_utc())
    expired_rows = expired_q.with_entities(URLMap.slug).all()
    expired_slugs = [r.slug for r in expired_rows if r.slug]

    # Delete them
    try:
        count = expired_q.delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.exception("Failed to cleanup expired URLs: %s", e)
        return jsonify({"ok": False, "error": "Cleanup failed"}), 500

    # Remove Redis keys for removed slugs (best-effort)
    if r and expired_slugs:
        try:
            with r.pipeline() as pipe:
                for s in expired_slugs:
                    pipe.delete(f"slug:{s}")
                    pipe.delete(f"stats:{s}")
                # cannot reliably delete url:{long_url} entries without reading long_url; skip
                pipe.execute()
        except Exception:
            logging.debug("Redis cleanup for expired slugs failed")

    return jsonify({"ok": True, "deleted": int(count), "msg": "Expired URLs removed"}), 200

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
# Auto backup thread at 23:59 daily (best-effort)
# -----------------------------
def daily_backup_thread():
    while True:
        try:
            now = datetime.now()
            target = now.replace(hour=23, minute=59, second=0, microsecond=0)
            if now > target:
                target += timedelta(days=1)
            sleep_seconds = (target - now).total_seconds()
            # sleep until target (could be large)
            time.sleep(max(1, sleep_seconds))
            try:
                push_db_to_github()
            except Exception as e:
                logging.error("Failed to push DB backup: %s", e)
        except Exception as e:
            logging.exception("Error in daily_backup_thread loop: %s", e)
            time.sleep(60)

threading.Thread(target=daily_backup_thread, daemon=True).start()

# -----------------------------
# Backup on shutdown (best-effort)
# -----------------------------
def safe_push():
    try:
        push_db_to_github()
    except Exception as e:
        logging.warning("push_db_to_github at shutdown failed: %s", e)

atexit.register(safe_push)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # In production, use gunicorn/uvicorn instead of Flask dev server.
    app.run(host="0.0.0.0", port=port, threaded=True)
