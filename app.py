import os
import re
import string
import secrets
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------
# Flask Setup
# -----------------------------
app = Flask(__name__)
CORS(app)

# -----------------------------
# Database Configuration
# -----------------------------
db_url = os.environ.get("DATABASE_URL", "sqlite:///urls.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -----------------------------
# Rate Limiting
# -----------------------------
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# -----------------------------
# Regex for valid slug
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")

# -----------------------------
# Database Model
# -----------------------------
class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------------
# Helper Functions
# -----------------------------
def json_response(ok: bool, msg: str, code=200):
    return jsonify({"ok": ok, "error" if not ok else "msg": msg}), code

def generate_slug(length=6):
    while True:
        slug = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        if not URLMap.query.filter_by(slug=slug).first():
            return slug

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ["http", "https"], parsed.netloc])
    except:
        return False

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False
        if parsed.hostname in ["localhost", "127.0.0.1"] or parsed.hostname.startswith("192.168."):
            return False
        return True
    except:
        return False

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    return response

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/shorten", methods=["POST"])
@limiter.limit("1/second")  # Limit 1 request/sec per IP
def shorten():
    data = request.get_json()
    if not data or "url" not in data:
        return json_response(False, "Missing URL", 400)

    long_url = data["url"].strip()
    custom_slug = data.get("slug", "").strip()
    expiry_days = data.get("expiry_days")

    if not is_valid_url(long_url) or not is_safe_url(long_url):
        return json_response(False, "Invalid or unsafe URL", 400)

    # Slug validation
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return json_response(False, "Invalid slug format", 400)
        if URLMap.query.filter_by(slug=custom_slug).first():
            return json_response(False, "Slug already taken", 400)
        slug = custom_slug
    else:
        slug = generate_slug()

    # Expiry
    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if days > 0:
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return json_response(False, "Invalid expiry value", 400)

    # Save to DB
    new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
    db.session.add(new_entry)
    db.session.commit()

    short_url = request.url_root.replace("http://", "https://") + slug
    logger.info(f"URL shortened: {slug} -> {long_url}")

    return jsonify({
        "ok": True,
        "code": slug,
        "msg": "URL shortened successfully!",
        "short_url": short_url
    })

@app.route("/<slug>")
def redirect_slug(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
    if entry:
        if entry.expires_at and entry.expires_at < datetime.utcnow():
            return json_response(False, "Link expired", 410)
        entry.clicks += 1
        db.session.commit()
        return redirect(entry.long_url, code=301)
    return json_response(False, "Slug not found", 404)

@app.route("/api/v1/stats/<slug>")
def stats(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
    if entry:
        return jsonify({
            "ok": True,
            "slug": entry.slug,
            "url": entry.long_url,
            "clicks": entry.clicks,
            "created_at": entry.created_at.isoformat(),
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "short_url": request.url_root.replace("http://", "https://") + entry.slug
        })
    return json_response(False, "Slug not found", 404)

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return json_response(False, "Endpoint not found", 404)

@app.errorhandler(429)
def ratelimit_handler(e):
    return json_response(False, "Too many requests. Please wait.", 429)

@app.errorhandler(500)
def server_error(e):
    return json_response(False, "Internal server error", 500)

# -----------------------------
# CLI Command to Cleanup Expired URLs
# -----------------------------
@app.cli.command("cleanup_expired")
def cleanup_expired():
    expired = URLMap.query.filter(URLMap.expires_at < datetime.utcnow()).all()
    for entry in expired:
        db.session.delete(entry)
    db.session.commit()
    print(f"Deleted {len(expired)} expired URLs")

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
