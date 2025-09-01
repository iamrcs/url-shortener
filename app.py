import os
import re
import string
import random
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)

# SQLite Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///urls.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Regex for valid slug
slug_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,}$")


# DB Model
class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    long_url = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# Generate random slug
def generate_slug(length=6):
    chars = string.ascii_letters + string.digits
    while True:
        slug = "".join(random.choices(chars, k=length))
        if not URLMap.query.filter_by(slug=slug).first():
            return slug


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/shorten", methods=["POST"])
def shorten():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    long_url = data["url"].strip()
    custom_slug = data.get("slug", "").strip()

    # Validate custom slug
    if custom_slug:
        if not slug_pattern.match(custom_slug):
            return jsonify({"ok": False, "error": "Invalid slug format"}), 400
        if URLMap.query.filter_by(slug=custom_slug).first():
            return jsonify({"ok": False, "error": "Slug already taken"}), 400
        slug = custom_slug
    else:
        slug = generate_slug()

    # Save mapping
    new_entry = URLMap(slug=slug, long_url=long_url)
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({
        "ok": True,
        "code": slug,
        "msg": "URL shortened successfully!"
    })


@app.route("/<slug>")
def redirect_slug(slug):
    entry = URLMap.query.filter_by(slug=slug).first()
    if entry:
        return redirect(entry.long_url)
    return jsonify({"ok": False, "error": "Slug not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
