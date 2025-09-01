from flask import Flask, request, render_template, redirect, url_for, jsonify
import sqlite3, string, random, os

app = Flask(__name__)
DB_NAME = "urls.db"

# -------------------------
# Database Setup
# -------------------------
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE,
                long_url TEXT
            )
        """)
        conn.commit()

# -------------------------
# Slug Generator
# -------------------------
def generate_slug(length=6):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))

def is_slug_taken(slug):
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM urls WHERE slug=?", (slug,))
        return cur.fetchone() is not None

def create_unique_slug():
    slug = generate_slug()
    while is_slug_taken(slug):
        slug = generate_slug()
    return slug

# -------------------------
# Routes
# -------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        long_url = request.form.get("long_url").strip()
        custom_slug = request.form.get("custom_slug", "").strip()

        if not long_url:
            return render_template("index.html", error="URL is required!")

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()

            # Check duplicate long_url if no custom slug provided
            if not custom_slug:
                cur.execute("SELECT slug FROM urls WHERE long_url=?", (long_url,))
                row = cur.fetchone()
                if row:
                    short_url = request.host_url + row[0]
                    return render_template("index.html", short_url=short_url)

            # If custom slug provided
            if custom_slug:
                if is_slug_taken(custom_slug):
                    return render_template("index.html", error="Slug already taken, try another!")
                slug = custom_slug
            else:
                slug = create_unique_slug()

            cur.execute("INSERT INTO urls (slug, long_url) VALUES (?, ?)", (slug, long_url))
            conn.commit()

            short_url = request.host_url + slug
            return render_template("index.html", short_url=short_url)

    return render_template("index.html")

@app.route("/<slug>")
def redirect_slug(slug):
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("SELECT long_url FROM urls WHERE slug=?", (slug,))
        row = cur.fetchone()
        if row:
            return redirect(row[0])
        return render_template("index.html", error="Short URL not found!")

# -------------------------
# API Endpoint
# -------------------------
@app.route("/api/shorten", methods=["POST"])
def api_shorten():
    data = request.json
    long_url = data.get("long_url")
    custom_slug = data.get("custom_slug", "").strip()

    if not long_url:
        return jsonify({"error": "URL is required!"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()

        # Check duplicate
        if not custom_slug:
            cur.execute("SELECT slug FROM urls WHERE long_url=?", (long_url,))
            row = cur.fetchone()
            if row:
                return jsonify({"short_url": request.host_url + row[0]})

        # Custom slug
        if custom_slug:
            if is_slug_taken(custom_slug):
                return jsonify({"error": "Slug already taken!"}), 409
            slug = custom_slug
        else:
            slug = create_unique_slug()

        cur.execute("INSERT INTO urls (slug, long_url) VALUES (?, ?)", (slug, long_url))
        conn.commit()

        return jsonify({"short_url": request.host_url + slug})

# -------------------------
# Init DB
# -------------------------
if not os.path.exists(DB_NAME):
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
