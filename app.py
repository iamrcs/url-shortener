import os
import re
import string
import random
import ipaddress
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
import logging

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Flask App & Config
# -----------------------------
class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///urls.db")

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Fix Postgres URL for SQLAlchemy if needed
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(app)

# Rate Limiter
limiter = Limiter(get_remote_address, app=app)

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    return response

# -----------------------------
# Regex for valid slug
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")
BLACKLISTED_DOMAINS = ["example.com", "malicious.com"]

# -----------------------------
# Database Models
# -----------------------------
class URLMap(db.Model):
    __tablename__ = "url_map"  # fixed table name
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, unique=True, nullable=False)  # Prevent duplicate URLs
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

class ClickLog(db.Model):
    __tablename__ = "click_log"  # fixed table name
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("url_map.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    referrer = db.Column(db.String(500))
    user_agent = db.Column(db.String(500))

with app.app_context():
    db.create_all()

# -----------------------------
# Helper Functions
# -----------------------------
def generate_slug(length=6, url=None):
    chars = string.ascii_letters + string.digits
    for _ in range(10):
        slug = "".join(random.choices(chars, k=length))
        if not URLMap.query.filter_by(slug=slug).first():
            return slug
    # fallback deterministic hash
    if url:
        slug = hashlib.md5(url.encode()).hexdigest()[:length]
        if not URLMap.query.filter_by(slug=slug).first():
            return slug
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return False

        # Block blacklisted domains
        if any(domain in parsed.hostname for domain in BLACKLISTED_DOMAINS):
            return False

        # Block local/private IPs
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            pass  # Not an IP

        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
        if parsed.hostname == "localhost" or parsed.hostname.startswith(private_prefixes):
            return False

        return True
    except Exception:
        return False

def enforce_https(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme == "http":
        url = url.replace("http://", "https://", 1)
    return url

def get_existing_slug_for_url(url: str):
    existing = URLMap.query.filter_by(long_url=url).first()
    return existing.slug if existing else None

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("1/second")
def shorten():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    long_url = data.get("url", "").strip()
    custom_slug = data.get("slug", "").strip()
    expiry_days = data.get("expiry_days")

    # Validate URL
    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # Enforce HTTPS
    long_url = enforce_https(long_url)

    # Avoid duplicate URLs
    existing_slug = get_existing_slug_for_url(long_url)
    if existing_slug and not custom_slug:
        short_url = request.host_url + existing_slug
        return jsonify({
            "ok": True,
            "code": existing_slug,
            "short_url": short_url,
            "msg": "URL already shortened"
        })

    # Validate slug
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if URLMap.query.filter_by(slug=custom_slug).first():
            return jsonify({"ok": False, "error": "Slug already taken"}), 400
        slug = custom_slug
    else:
        try:
            slug = generate_slug(url=long_url)
        except Exception as e:
            logging.error(str(e))
            return jsonify({"ok": False, "error": "Could not generate unique slug"}), 500

    # Expiry handling
    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    # Save to DB
    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    try:
        db.session.add(new_entry)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        slug = generate_slug(url=long_url)
        new_entry.slug = slug
        db.session.add(new_entry)
        db.session.commit()

    logging.info(f"Created new short URL: {slug} -> {long_url}")
    return jsonify({
        "ok": True,
        "code": slug,
        "short_url": request.host_url + slug,
        "msg": "URL shortened successfully!"
    })

@app.route("/<slug>")
def redirect_slug(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
    if entry:
        if entry.expires_at and entry.expires_at < datetime.utcnow():
            return jsonify({"ok": False, "error": "Link expired"}), 410
        entry.clicks += 1
        entry.last_clicked = datetime.utcnow()
        db.session.commit()

        # Log click details
        click = ClickLog(
            url_id=entry.id,
            referrer=request.referrer,
            user_agent=request.headers.get("User-Agent")
        )
        db.session.add(click)
        db.session.commit()

        return redirect(entry.long_url, code=301)
    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/api/stats/<slug>")
def stats(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
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
        })
    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/cleanup", methods=["POST"])
def cleanup():
    count = URLMap.query.filter(URLMap.expires_at < datetime.utcnow()).delete()
    db.session.commit()
    return jsonify({"ok": True, "deleted": count, "msg": "Expired URLs removed"})

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
    logging.error(str(e))
    return jsonify({"ok": False, "error": "Internal server error"}), 500

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
