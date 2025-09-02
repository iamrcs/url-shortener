import os
import re
import string
import random
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
import logging
import redis

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Flask App & Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
    RATE_LIMIT_DEFAULT = "200 per day;50 per hour"  # not used directly, but left for clarity
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

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
# Rate Limiter (with safe Redis fallback)
# -----------------------------
storage_uri = "memory://"
REDIS_URL = app.config.get("REDIS_URL")
if REDIS_URL:
    try:
        _rc = redis.from_url(REDIS_URL)
        _rc.ping()  # verify connectivity
        storage_uri = REDIS_URL
        logging.info("Rate limiter using Redis storage.")
    except Exception as e:
        logging.warning("Redis unavailable (%s). Falling back to in-memory rate limiting.", e)

# Flask-Limiter changed API across versions; support both styles.
try:
    limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri, app=app)
except TypeError:
    limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri)
    limiter.init_app(app)

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
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
    # Keeping long_url unique => a URL maps to a single slug.
    long_url = db.Column(db.Text, unique=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
def generate_slug(length=6, attempts=20):
    chars = string.ascii_letters + string.digits
    for _ in range(attempts):
        slug = "".join(random.choices(chars, k=length))
        if not URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first():
            return slug
    raise Exception("Failed to generate unique slug after attempts")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False

        hostname = parsed.hostname or ""

        # Reject localhost/private IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except Exception:
            # Not an IP literal -> fine
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

def get_existing_by_url(url: str):
    return URLMap.query.filter_by(long_url=url).first()

def slug_exists(slug: str) -> bool:
    return URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first() is not None

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("1/second")
def shorten():
    # Accept JSON or form data (avoids AttributeError when frontend posts form-encoded)
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict() if request.form else {}

    if not data or "url" not in data:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    long_url = (data.get("url") or "").strip()
    custom_slug = (data.get("slug") or "").strip()
    expiry_days = data.get("expiry_days")

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # If this URL already exists, always return the existing mapping,
    # regardless of whether a custom slug was provided (because long_url is unique).
    existing = get_existing_by_url(long_url)
    if existing:
        return jsonify({
            "ok": True,
            "code": existing.slug,
            "short_url": request.host_url + existing.slug,
            "msg": "URL already shortened"
        }), 200

    # Validate custom slug (if provided)
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format (A–Z, a–z, 0–9, '-', '_', min 3)"}), 400
        if slug_exists(custom_slug):
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
        slug = custom_slug
    else:
        try:
            slug = generate_slug()
        except Exception as e:
            logging.error("Slug generation failed: %s", e)
            return jsonify({"ok": False, "error": "Could not generate unique slug"}), 500

    # Expiry handling
    expires_at = None
    if expiry_days not in (None, ""):
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = datetime.utcnow() + timedelta(days=days)
            else:
                return jsonify({"ok": False, "error": "Expiry days must be between 1 and 3650"}), 400
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    # Persist
    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    try:
        db.session.add(new_entry)
        db.session.commit()
    except IntegrityError as ie:
        # Handle race conditions (slug or URL collision)
        db.session.rollback()
        logging.warning("IntegrityError on insert: %s", ie)

        # If slug collided, retry with generated slug (only if user didn't force a specific slug)
        if not custom_slug:
            try:
                slug = generate_slug(length=6, attempts=20)
                new_entry.slug = slug
                db.session.add(new_entry)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logging.error("Retry insert failed: %s", e)
                return jsonify({"ok": False, "error": "Database error"}), 500
        else:
            # Custom slug conflict or URL already exists at DB level
            # (URL is unique => return info to client)
            existing = get_existing_by_url(long_url)
            if existing:
                return jsonify({
                    "ok": True,
                    "code": existing.slug,
                    "short_url": request.host_url + existing.slug,
                    "msg": "URL already shortened"
                }), 200
            return jsonify({"ok": False, "error": "Slug already taken"}), 409
    except Exception as e:
        db.session.rollback()
        logging.error("Unexpected DB error: %s", e)
        return jsonify({"ok": False, "error": "Database error"}), 500

    logging.info("Created short URL: %s -> %s", slug, long_url)
    return jsonify({
        "ok": True,
        "code": slug,
        "short_url": request.host_url + slug,
        "msg": "URL shortened successfully!"
    }), 201

@app.route("/<slug>")
def redirect_slug(slug):
    entry = URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first()
    if entry:
        if entry.expires_at and entry.expires_at < datetime.utcnow():
            return jsonify({"ok": False, "error": "Link expired"}), 410
        entry.clicks += 1
        entry.last_clicked = datetime.utcnow()
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error("Failed to update click count: %s", e)
        return redirect(entry.long_url, code=301)
    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/api/stats/<slug>")
def stats(slug):
    entry = URLMap.query.filter(db.func.lower(URLMap.slug) == slug.lower()).first()
    if entry:
        return jsonify({
            "ok": True,
            "slug": entry.slug,
            "url": entry.long_url,
            "clicks": entry.clicks,
            "created_at": entry.created_at.isoformat(),
            "last_clicked": entry.last_clicked.isoformat() if entry.last_clicked else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "short_url": request.host_url + entry.slug
        }), 200
    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/cleanup", methods=["POST"])
def cleanup():
    # Delete expired rows; rows with NULL expires_at are ignored by the comparison
    count = URLMap.query.filter(URLMap.expires_at < datetime.utcnow()).delete()
    db.session.commit()
    return jsonify({"ok": True, "deleted": count, "msg": "Expired URLs removed"}), 200

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Endpoint not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please wait before trying again."}), 429

@app.errorhandler(500)
def server_error(e):
    logging.exception("Server error: %s", e)
    return jsonify({"ok": False, "error": "Internal server error"}), 500

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
