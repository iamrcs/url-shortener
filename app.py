import os
import re
import string
import random
from urllib.parse import urlparse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
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
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
cache = Cache(app)

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
    for _ in range(10):  # Avoid infinite loop
        slug = "".join(random.choices(chars, k=length))
        if not URLMap.query.filter_by(slug=slug).first():
            return slug
    raise Exception("Failed to generate unique slug")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return False
        # Prevent redirects to localhost or private IPs
        if parsed.hostname in ["localhost", "127.0.0.1"] or parsed.hostname.startswith("192.168."):
            return False
        return True
    except Exception:
        return False

@cache.memoize()
def get_url(slug):
    return URLMap.query.filter_by(slug=slug).first()

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("1/second")
def shorten():
    data = request.get_json(force=True)
    if not data or "url" not in data:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    long_url = data.get("url", "").strip()
    custom_slug = data.get("slug", "").strip()
    expiry_days = data.get("expiry_days")  # optional

    # Validate URL
    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    # Validate slug
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if URLMap.query.filter_by(slug=custom_slug).first():
            return jsonify({"ok": False, "error": "Slug already taken"}), 400
        slug = custom_slug
    else:
        try:
            slug = generate_slug()
        except Exception as e:
            logging.error(str(e))
            return jsonify({"ok": False, "error": "Could not generate unique slug"}), 500

    # Expiry handling
    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:  # Max 10 years
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    # Save to DB
    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
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
    entry = get_url(slug)
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
    entry = get_url(slug)
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
