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

# Fix Postgres URL if needed
db_url = app.config["DATABASE_URL"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app)

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# -----------------------------
# Regex for valid slug
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")

# -----------------------------
# Database Model
# -----------------------------
class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
def generate_slug(length=6):
    chars = string.ascii_letters + string.digits
    while True:
        slug = "".join(random.choices(chars, k=length))
        if not URLMap.query.filter_by(slug=slug).first():
            return slug

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return False
        # Prevent private IPs
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            # Not an IP, ignore
            pass
        if parsed.hostname in ["localhost"] or parsed.hostname.startswith(("192.168.", "10.", "172.")):
            return False
        return True
    except Exception:
        return False

def create_or_get_short_url(long_url, custom_slug=None, expires_at=None):
    """Return existing short URL if available or create a new one"""
    # Check existing non-expired URL
    existing = URLMap.query.filter_by(long_url=long_url).filter(
        (URLMap.expires_at == None) | (URLMap.expires_at > datetime.utcnow())
    ).first()
    if existing:
        return existing, False  # False = not newly created

    # Use custom slug if valid
    slug = custom_slug if custom_slug else generate_slug()

    while True:
        try:
            new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
            db.session.add(new_entry)
            db.session.commit()
            return new_entry, True  # True = newly created
        except IntegrityError:
            db.session.rollback()
            slug = generate_slug()  # retry if slug already exists

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
    expiry_days = data.get("expiry_days")  # optional

    # Validate URL
    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # Validate custom slug
    if custom_slug and not slug_pattern.match(custom_slug):
        return jsonify({"ok": False, "error": "Invalid slug format"}), 400

    # Expiry handling
    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:  # max 10 years
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    # Create or get existing
    entry, created = create_or_get_short_url(long_url, custom_slug=custom_slug, expires_at=expires_at)

    return jsonify({
        "ok": True,
        "code": entry.slug,
        "short_url": request.host_url + entry.slug,
        "msg": "URL shortened successfully!" if created else "URL already shortened!"
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
