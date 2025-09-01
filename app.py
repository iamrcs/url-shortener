import re
import string
import random
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------- CONFIG ----------------
app = Flask(__name__, static_folder=".", template_folder=".")
CORS(app)

# SQLite Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///urls.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Flask-Limiter (rate limiting per IP)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# ---------------- MODEL ----------------
class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, nullable=False, index=True)
    target = db.Column(db.String(2048), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    clicks = db.Column(db.Integer, default=0)

    def is_expired(self):
        return self.expires_at and datetime.utcnow() > self.expires_at


# ---------------- HELPERS ----------------
def generate_slug(length=6):
    """Generate a random slug"""
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def validate_slug(slug):
    """Check allowed slug format"""
    return re.fullmatch(r"[A-Za-z0-9_-]{3,50}", slug) is not None


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    """Serve index.html frontend"""
    return app.send_static_file("index.html")


@app.route("/shorten", methods=["POST"])
@limiter.limit("1/second")  # one request per second per IP
def shorten():
    data = request.get_json() or {}

    long_url = data.get("url", "").strip()
    custom_slug = data.get("slug", "").strip()
    expiry_days = data.get("expiry_days")

    if not long_url:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    # Handle expiry
    expires_at = None
    if expiry_days:
        try:
            days = int(expiry_days)
            if days > 0:
                expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid expiry days"}), 400

    # Handle slug
    if custom_slug:
        if not validate_slug(custom_slug):
            return jsonify({
                "ok": False,
                "error": "Invalid slug. Use A–Z, a–z, 0–9, dash, underscore, min 3 chars"
            }), 400
        if URL.query.filter_by(slug=custom_slug).first():
            return jsonify({"ok": False, "error": "Slug already taken"}), 400
        slug = custom_slug
    else:
        # Generate unique slug
        slug = generate_slug()
        while URL.query.filter_by(slug=slug).first():
            slug = generate_slug()

    # Save to DB
    new_url = URL(slug=slug, target=long_url, expires_at=expires_at)
    db.session.add(new_url)
    db.session.commit()

    return jsonify({
        "ok": True,
        "code": slug,
        "msg": "Short URL created successfully"
    })


@app.route("/<slug>")
def redirect_slug(slug):
    """Redirect to original URL"""
    url_entry = URL.query.filter_by(slug=slug).first()
    if not url_entry:
        return jsonify({"ok": False, "error": "Short URL not found"}), 404

    if url_entry.is_expired():
        return jsonify({"ok": False, "error": "This link has expired"}), 410

    url_entry.clicks += 1
    db.session.commit()
    return redirect(url_entry.target)


@app.route("/stats/<slug>")
def stats(slug):
    """Get stats for a short URL"""
    url_entry = URL.query.filter_by(slug=slug).first()
    if not url_entry:
        return jsonify({"ok": False, "error": "Short URL not found"}), 404

    return jsonify({
        "ok": True,
        "slug": slug,
        "target": url_entry.target,
        "created_at": url_entry.created_at.isoformat(),
        "expires_at": url_entry.expires_at.isoformat() if url_entry.expires_at else None,
        "clicks": url_entry.clicks
    })


# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please wait."}), 429


# ---------------- MAIN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
