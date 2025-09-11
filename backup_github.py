import os
import base64
import requests
from datetime import datetime

GITHUB_REPO = os.environ.get("GITHUB_REPO")  # e.g., "username/url-shortener-backups"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # Personal access token
DB_PATH = "urls.db"  # Local DB path
BRANCH = "main"

def push_db_to_github():
    if not os.path.exists(DB_PATH):
        print("Database not found, skipping backup.")
        return

    with open(DB_PATH, "rb") as f:
        content = base64.b64encode(f.read()).decode()

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_PATH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    # Get SHA if file exists
    r = requests.get(url, headers=headers)
    sha = r.json()["sha"] if r.status_code == 200 else None

    data = {
        "message": f"Daily backup: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "content": content,
        "branch": BRANCH
    }
    if sha:
        data["sha"] = sha

    r = requests.put(url, headers=headers, json=data)
    if r.status_code in (200, 201):
        print("Database backup successful!")
    else:
        print("Failed to backup DB:", r.status_code, r.text)

def restore_db_from_github():
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_PATH}?ref={BRANCH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        content = base64.b64decode(r.json()["content"])
        with open(DB_PATH, "wb") as f:
            f.write(content)
        print("Database restored from GitHub")
    else:
        print("No backup found on GitHub. Starting with fresh DB.")
