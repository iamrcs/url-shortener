import os
import base64
import requests
from datetime import datetime

GITHUB_REPO = os.environ.get("GITHUB_REPO")  # e.g., "username/url-shortener-backups"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # Personal access token with repo scope
DB_PATH = "urls.db"  # Local DB path
BRANCH = os.environ.get("GITHUB_BRANCH", "main")

API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_PATH}"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}


def push_db_to_github():
    """Push local DB to GitHub repo as a commit."""
    if not os.path.exists(DB_PATH):
        print("⚠️ Database not found, skipping backup.")
        return

    try:
        with open(DB_PATH, "rb") as f:
            content = base64.b64encode(f.read()).decode()
    except Exception as e:
        print(f"❌ Failed to read DB file: {e}")
        return

    # Check if file exists in repo
    sha = None
    r = requests.get(API_URL, headers=HEADERS, params={"ref": BRANCH})
    if r.status_code == 200:
        try:
            sha = r.json().get("sha")
        except Exception:
            sha = None

    data = {
        "message": f"Backup: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "content": content,
        "branch": BRANCH
    }
    if sha:
        data["sha"] = sha

    r = requests.put(API_URL, headers=HEADERS, json=data)
    if r.status_code in (200, 201):
        print("✅ Database backup successful!")
    else:
        print("❌ Backup failed:", r.status_code, r.text)


def restore_db_from_github():
    """Restore latest DB from GitHub repo if available."""
    url = f"{API_URL}?ref={BRANCH}"
    r = requests.get(url, headers=HEADERS)

    if r.status_code == 200:
        try:
            content = r.json().get("content")
            if content:
                decoded = base64.b64decode(content)
                with open(DB_PATH, "wb") as f:
                    f.write(decoded)
                print("✅ Database restored from GitHub")
                return
        except Exception as e:
            print(f"❌ Failed to decode/restore DB: {e}")

    print("⚠️ No backup found on GitHub. Starting fresh DB.")
