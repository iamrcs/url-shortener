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
from apscheduler.schedulers.background import BackgroundScheduler
import redis
from rq import Queue

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
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30,
    'pool_recycle': 1800
}

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app)

# -----------------------------
# Redis & RQ Setup
# -----------------------------
cache = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
queue = Queue(connection=cache)  # use same Redis instance

# -----------------------------
# Security Headers
# -----------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    return response

# -----------------------------
# Regex & Reserved Slugs
# -----------------------------
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")
RESERVED_SLUGS = {"admin", "login", "api", "signup", "stats", "shorten"}

# -----------------------------
# Database Models (URLMap first)
# -----------------------------
class URLMap(db.Model):
    __tablename__ = "urlmap"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, index=True, nullable=False)
    long_url = db.Column(db.Text, index=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_clicked = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

class Click(db.Model):
    __tablename__ = "click"
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("urlmap.id"), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
BASE62 = string.digits + string.ascii_letters

def encode_base62(num):
    if num == 0:
        return BASE62[0]
    arr = []
    base = len(BASE62)
    while num:
        num, rem = divmod(num, base)
        arr.append(BASE62[rem])
    arr.reverse()
    return ''.join(arr)

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return False
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            pass
        if parsed.hostname in ["localhost"] or parsed.hostname.startswith(("192.168.", "10.", "172.")):
            return False
        return True
    except Exception:
        return False

def create_or_get_short_url(long_url, custom_slug=None, expires_at=None):
    """Return existing short URL if available or create a new one"""
    cached_slug = cache.get(f"url:{long_url}")
    if cached_slug:
        entry = URLMap.query.filter_by(slug=cached_slug).first()
        if entry and (entry.expires_at is None or entry.expires_at > datetime.utcnow()):
            return entry, False

    existing = URLMap.query.filter_by(long_url=long_url).filter(
        (URLMap.expires_at == None) | (URLMap.expires_at > datetime.utcnow())
    ).first()
    if existing:
        cache.set(f"url:{long_url}", existing.slug, ex=3600)
        cache.set(f"slug:{existing.slug}", existing.long_url, ex=3600)
        return existing, False

    if custom_slug:
        slug = custom_slug
    else:
        # Use next ID + Base62 to ensure unique slug
        new_id = db.session.execute("SELECT nextval('urlmap_id_seq')").scalar() if "postgresql" in db_url else random.randint(100000, 999999)
        slug = encode_base62(new_id)

    while True:
        try:
            new_entry = URLMap(slug=slug, long_url=long_url, expires_at=expires_at)
            db.session.add(new_entry)
            db.session.commit()
            cache.set(f"url:{long_url}", slug, ex=3600)
            cache.set(f"slug:{slug}", long_url, ex=3600)
            return new_entry, True
        except IntegrityError:
            db.session.rollback()
            slug = encode_base62(random.randint(100000, 999999))

def record_click_async(entry_id, ip, ua):
    entry = URLMap.query.get(entry_id)
    if entry:
        click = Click(url_id=entry_id, ip_address=ip, user_agent=ua)
        db.session.add(click)
        entry.clicks += 1
        entry.last_clicked = datetime.utcnow()
        db.session.commit()

def cleanup_expired_urls():
    with app.app_context():
        count = URLMap.query.filter(URLMap.expires_at < datetime.utcnow()).delete()
        db.session.commit()
        logging.info(f"Cleanup: Removed {count} expired URLs")

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_expired_urls, trigger="interval", hours=24)
scheduler.start()

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

    if not is_valid_url(long_url):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if custom_slug.lower() in RESERVED_SLUGS:
            return jsonify({"ok": False, "error": "Slug is reserved"}), 400

    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if 0 < days <= 3650:
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry value"}), 400

    entry, created = create_or_get_short_url(long_url, custom_slug=custom_slug, expires_at=expires_at)

    return jsonify({
        "ok": True,
        "code": entry.slug,
        "short_url": request.host_url + entry.slug,
        "msg": "URL shortened successfully!" if created else "URL already shortened!",
        "short_url_exists": not created
    })

@app.route("/<slug>")
def redirect_slug(slug):
    long_url = cache.get(f"slug:{slug}")
    if long_url:
        entry = URLMap.query.filter_by(slug=slug).first()
    else:
        entry = URLMap.query.filter_by(slug=slug).first()
        if entry:
            cache.set(f"slug:{slug}", entry.long_url, ex=3600)

    if entry:
        if entry.expires_at and entry.expires_at < datetime.utcnow():
            return jsonify({"ok": False, "error": "Link expired"}), 410
        queue.enqueue(record_click_async, entry.id, request.remote_addr, request.headers.get("User-Agent"))
        return redirect(entry.long_url, code=301)
    return jsonify({"ok": False, "error": "Slug not found"}), 404

@app.route("/api/stats/<slug>")
def stats(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
    if entry:
        clicks = Click.query.filter_by(url_id=entry.id).all()
        return jsonify({
            "ok": True,
            "slug": entry.slug,
            "url": entry.long_url,
            "clicks": entry.clicks,
            "created_at": entry.created_at.isoformat(),
            "last_clicked": entry.last_clicked.isoformat() if entry.last_clicked else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "short_url": request.host_url + entry.slug,
            "click_details": [
                {"ip": c.ip_address, "user_agent": c.user_agent, "timestamp": c.created_at.isoformat()}
                for c in clicks
            ]
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
