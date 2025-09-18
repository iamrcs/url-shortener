# app.py
import os
import re
import string
import random
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, redirect, render_template, send_from_directory
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
from werkzeug.utils import safe_join

# Optional: functions to backup/restore DB to Github (your existing module)
from backup_github import push_db_to_github, restore_db_from_github

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# -----------------------------
# Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATE_LIMIT_DEFAULT = "200 per day;50 per hour"
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 20)),
    }

# -----------------------------
# Flask app
# -----------------------------
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
# Restore DB from GitHub (if available)
# -----------------------------
try:
    restore_db_from_github()
except Exception as e:
    logger.warning("restore_db_from_github failed or not configured: %s", e)

# -----------------------------
# Redis client
# -----------------------------
REDIS_URL = app.config.get("REDIS_URL")
r = None
if REDIS_URL:
    try:
        r = redis.from_url(REDIS_URL, decode_responses=False)
        r.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning("Redis unavailable: %s", e)
        r = None

# -----------------------------
# Rate limiter
# -----------------------------
storage_uri = REDIS_URL if r else "memory://"
limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri, app=app)

# -----------------------------
# Security headers
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
# Database model
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
# Helpers
# -----------------------------
def generate_slug(length=6, attempts=50):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length))
        # fast redis check
        if r:
            try:
                if r.exists(f"slug:{slug}"):
                    continue
            except Exception:
                pass
        # db check (case-insensitive)
        if not db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug.lower()).first():
            return slug
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = parsed.hostname or ""
        # disallow direct private ip addresses
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # not an ip, OK (domain)
            pass

        # disallow common private host prefixes and localhost
        private_prefixes = (
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31."
        )
        if hostname == "localhost" or hostname.startswith(private_prefixes):
            return False

        return True
    except Exception:
        return False

def get_existing_by_url(url: str):
    try:
        if r:
            cached_slug = r.get(f"url:{url}")
            if cached_slug:
                # decode bytes to string if necessary
                return cached_slug.decode() if isinstance(cached_slug, (bytes, bytearray)) else cached_slug
    except Exception:
        pass

    entry = db.session.query(URLMap).filter_by(long_url=url).first()
    if entry and r:
        try:
            r.set(f"url:{url}", entry.slug, ex=3600*24*30)
        except Exception:
            pass
    return entry.slug if entry else None

def slug_exists(slug: str) -> bool:
    try:
        if r:
            if r.exists(f"slug:{slug}"):
                return True
    except Exception:
        pass
    return db.session.query(URLMap.slug).filter(db.func.lower(URLMap.slug) == slug.lower()).first() is not None

# -----------------------------
# Serve assets from /assets but accessible at root too
# -----------------------------
# We use before_request so it doesn't conflict with other registered endpoints like /api/...
@app.before_request
def serve_asset_if_exists():
    # don't attempt to serve assets for API, static, or admin paths
    path = request.path.lstrip("/")
    if not path:
        return None

    # protect API and known endpoints from being hijacked
    protected_prefixes = ("api/", "static/", "favicon.ico", ".well-known/")
    if any(path.startswith(p) for p in protected_prefixes):
        return None

    # only serve actual files that exist in /assets or /.well-known
    try:
        # serve from assets at e.g. /ads.txt when file exists in assets/ads.txt
        assets_dir = os.path.join(app.root_path, "assets")
        candidate = safe_join(assets_dir, path)
        if candidate and os.path.isfile(candidate):
            return send_from_directory(assets_dir, path)

        # also allow direct /.well-known/<file>
        wk_dir = os.path.join(app.root_path, ".well-known")
        candidate_wk = safe_join(wk_dir, path)
        if candidate_wk and os.path.isfile(candidate_wk):
            # serve the file (path likely like 'security.txt' or similar)
            return send_from_directory(wk_dir, path)
    except Exception:
        # if safe_join or send_from_directory raises, just continue normal routing
        return None

    return None

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

    # if no custom slug, return existing shortened if present
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
    except Exception as e:
        db.session.rollback()
        logger.exception("DB commit failed: %s", e)
        return jsonify({"ok": False, "error": "Database error"}), 500

    # cache in redis where available
    if r:
        try:
            with r.pipeline() as pipe:
                pipe.set(f"url:{long_url}", slug, ex=3600*24*30)
                pipe.set(f"slug:{slug}", long_url, ex=3600*24*30)
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

# Redirect slug (last catch-all for slugs)
@app.route("/<slug>")
def redirect_slug(slug):
    # Skip obvious static like 'api' or 'static' - but these shouldn't reach here due to other routes
    long_url = None
    entry = None

    # try redis cache first
    if r:
        try:
            cached = r.get(f"slug:{slug}")
            if cached:
                long_url = cached.decode() if isinstance(cached, (bytes, bytearray)) else cached
        except Exception:
            pass

    # db lookup if not cached
    if not long_url:
        entry = db.session.query(URLMap).filter(db.func.lower(URLMap.slug) == slug.lower()).first()
        if entry:
            long_url = entry.long_url
            if r:
                try:
                    r.set(f"slug:{slug}", long_url, ex=3600*24*30)
                except Exception:
                    pass

    # check expiry (if entry exists in db)
    if entry and entry.expires_at and entry.expires_at < datetime.now(timezone.utc):
        return jsonify({"ok": False, "error": "Link expired"}), 410

    if long_url:
        # update click counters (prefer redis increment)
        now_iso = datetime.now(timezone.utc).isoformat()
        if r:
            try:
                r.incr(f"clicks:{slug}", amount=1)
                r.set(f"lastclick:{slug}", now_iso)
            except Exception:
                # fallback to DB update if redis fails
                try:
                    if entry:
                        entry.clicks = entry.clicks + 1
                        entry.last_clicked = datetime.now(timezone.utc)
                        db.session.commit()
                except Exception:
                    db.session.rollback()
        else:
            # no redis: update DB directly
            try:
                if entry:
                    entry.clicks = entry.clicks + 1
                    entry.last_clicked = datetime.now(timezone.utc)
                    db.session.commit()
            except Exception:
                db.session.rollback()

        return redirect(long_url, code=301)

    return jsonify({"ok": False, "error": "Slug not found"}), 404

# -----------------------------
# API: Stats
# -----------------------------
@app.route("/api/stats/<slug>")
def stats(slug):
    entry = db.session.query(URLMap).filter(db.func.lower(URLMap.slug) == slug.lower()).first()
    if entry:
        clicks = entry.clicks or 0
        last_clicked = entry.last_clicked

        if r:
            try:
                rc = r.get(f"clicks:{slug}")
                if rc:
                    rc_val = int(rc.decode() if isinstance(rc, (bytes, bytearray)) else rc)
                    clicks += rc_val
            except Exception:
                pass

            try:
                rl = r.get(f"lastclick:{slug}")
                if rl:
                    rl_decoded = rl.decode() if isinstance(rl, (bytes, bytearray)) else rl
                    last_clicked = datetime.fromisoformat(rl_decoded)
            except Exception:
                pass

        return jsonify({
            "ok": True,
            "slug": entry.slug,
            "url": entry.long_url,
            "clicks": clicks,
            "created_at": entry.created_at.isoformat(),
            "last_clicked": last_clicked.isoformat() if last_clicked else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "short_url": request.host_url + entry.slug
        }), 200

    return jsonify({"ok": False, "error": "Slug not found"}), 404

# -----------------------------
# Cleanup expired links
# -----------------------------
@app.route("/cleanup", methods=["POST"])
def cleanup():
    try:
        count = URLMap.query.filter(
            URLMap.expires_at != None,
            URLMap.expires_at < datetime.now(timezone.utc)
        ).delete()
        db.session.commit()
        return jsonify({"ok": True, "deleted": count, "msg": "Expired URLs removed"}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception("Cleanup failed: %s", e)
        return jsonify({"ok": False, "error": "Cleanup failed"}), 500

# -----------------------------
# Error handlers
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
# Flush Redis click counts to DB (safe)
# -----------------------------
def flush_clicks_loop():
    while True:
        time.sleep(60)
        if not r:
            continue
        try:
            # use scan_iter to avoid blocking on many keys
            for key in r.scan_iter(match="clicks:*"):
                try:
                    key_str = key.decode() if isinstance(key, (bytes, bytearray)) else key
                    slug = key_str.split(":", 1)[1]
                    count_raw = r.get(key)
                    count = int(count_raw.decode() if isinstance(count_raw, (bytes, bytearray)) else (count_raw or 0))
                    if count > 0:
                        entry = db.session.query(URLMap).filter_by(slug=slug).first()
                        if entry:
                            entry.clicks = (entry.clicks or 0) + count
                            last_raw = r.get(f"lastclick:{slug}")
                            if last_raw:
                                try:
                                    last_iso = last_raw.decode() if isinstance(last_raw, (bytes, bytearray)) else last_raw
                                    entry.last_clicked = datetime.fromisoformat(last_iso)
                                except Exception:
                                    pass
                            db.session.commit()
                        # remove the redis count after flushing
                        try:
                            r.delete(key)
                        except Exception:
                            pass
                except Exception:
                    # keep going with other keys
                    continue
        except Exception as e:
            logger.exception("Flush clicks failed: %s", e)

t = threading.Thread(target=flush_clicks_loop, daemon=True)
t.start()

# -----------------------------
# Daily backup thread
# -----------------------------
def daily_backup_thread():
    while True:
        now = datetime.now()
        target = now.replace(hour=23, minute=59, second=0, microsecond=0)
        if now > target:
            target += timedelta(days=1)
        sleep_seconds = max(1, (target - now).total_seconds())
        time.sleep(sleep_seconds)
        try:
            push_db_to_github()
        except Exception as e:
            logger.exception("Failed to push DB backup: %s", e)

try:
    thread_backup = threading.Thread(target=daily_backup_thread, daemon=True)
    thread_backup.start()
except Exception as e:
    logger.warning("Could not start backup thread: %s", e)

# -----------------------------
# Backup on shutdown (best-effort)
# -----------------------------
try:
    atexit.register(push_db_to_github)
except Exception:
    pass

# -----------------------------
# Run app
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
