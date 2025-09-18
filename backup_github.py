import os
import base64
import requests
from datetime import datetime

# -----------------------------
# Config
# -----------------------------
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # e.g., "username/url-shortener-backups"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # Personal access token with repo scope
DB_PATH = os.environ.get("DB_PATH", "urls.db")  # Local DB path
BRANCH = os.environ.get("GITHUB_BRANCH", "main")

API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_PATH}"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}


# -----------------------------
# Push DB to GitHub
# -----------------------------
def push_db_to_github():
    """Push local DB to GitHub repo as a commit."""
    if not GITHUB_REPO or not GITHUB_TOKEN:
        print("⚠️ GitHub backup skipped: Missing GITHUB_REPO or GITHUB_TOKEN.")
        return

    if not os.path.exists(DB_PATH):
        print("⚠️ Database not found, skipping backup.")
        return

    try:
        with open(DB_PATH, "rb") as f:
            content = base64.b64encode(f.read()).decode()
    except Exception as e:
        print(f"❌ Failed to read DB file: {e}")
        return

    # Check if file already exists in repo
    sha = None
    try:
        r = requests.get(API_URL, headers=HEADERS, params={"ref": BRANCH}, timeout=15)
        if r.status_code == 200:
            sha = r.json().get("sha")
    except Exception as e:
        print(f"⚠️ Could not check existing file on GitHub: {e}")

    data = {
        "message": f"DB Backup: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "content": content,
        "branch": BRANCH
    }
    if sha:
        data["sha"] = sha  # Required to update existing file

    try:
        r = requests.put(API_URL, headers=HEADERS, json=data, timeout=30)
        if r.status_code in (200, 201):
            print("✅ Database backup successful!")
        else:
            print("❌ Backup failed:", r.status_code, r.text)
    except Exception as e:
        print(f"❌ Backup request failed: {e}")


# -----------------------------
# Restore DB from GitHub
# -----------------------------
def restore_db_from_github():
    """Restore latest DB from GitHub repo if available."""
    if not GITHUB_REPO or not GITHUB_TOKEN:
        print("⚠️ GitHub restore skipped: Missing GITHUB_REPO or GITHUB_TOKEN.")
        return

    try:
        r = requests.get(f"{API_URL}?ref={BRANCH}", headers=HEADERS, timeout=20)
        if r.status_code == 200:
            content = r.json().get("content")
            if content:
                try:
                    decoded = base64.b64decode(content)
                    with open(DB_PATH, "wb") as f:
                        f.write(decoded)
                    print("✅ Database restored from GitHub")
                    return
                except Exception as e:
                    print(f"❌ Failed to decode/restore DB: {e}")
        elif r.status_code == 404:
            print("⚠️ No backup found on GitHub. Starting fresh DB.")
        else:
            print(f"❌ Restore request failed: {r.status_code} {r.text}")
    except Exception as e:
        print(f"❌ GitHub restore failed: {e}")
