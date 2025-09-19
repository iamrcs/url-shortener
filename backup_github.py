# backup_github.py
"""
Simple GitHub-backed DB backup/restore helpers.

Environment variables (all optional; defaults shown):
  GITHUB_TOKEN        -> GitHub personal access token (recommended)
  GITHUB_REPO         -> "owner/repo" where backups are stored
  GITHUB_PATH         -> path in repo to store DB (default: backups/urls.db)
  GITHUB_BRANCH       -> branch to use (default: main)
  GITHUB_COMMIT_NAME  -> committer name (default: "auto-backup")
  GITHUB_COMMIT_EMAIL -> committer email (default: "backup@example.com")
  GITHUB_USE_GIT      -> "1" to attempt git CLI fallback (defaults to API only)
  LOCAL_DB_PATH       -> local path to DB file (default: urls.db)

Functions:
  push_db_to_github(db_path=None) -> True on success (raises Exception on failure)
  restore_db_from_github(db_path=None) -> True on success (raises Exception on failure)
"""
from __future__ import annotations
import os
import base64
import json
import logging
import time
from typing import Optional
import requests
import subprocess
import shutil

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------- Defaults & helpers ----------
GITHUB_API = "https://api.github.com"
DEFAULT_LOCAL_DB = os.environ.get("LOCAL_DB_PATH", "urls.db")
DEFAULT_REPO = os.environ.get("GITHUB_REPO", "")
DEFAULT_PATH = os.environ.get("GITHUB_PATH", "backups/urls.db")
DEFAULT_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
DEFAULT_COMMIT_NAME = os.environ.get("GITHUB_COMMIT_NAME", "auto-backup")
DEFAULT_COMMIT_EMAIL = os.environ.get("GITHUB_COMMIT_EMAIL", "backup@example.com")
USE_GIT_FALLBACK = os.environ.get("GITHUB_USE_GIT", "0") == "1"

def _get_env_token(token: Optional[str]) -> Optional[str]:
    if token:
        return token
    return os.environ.get("GITHUB_TOKEN")

def _get_repo_arg(repo: Optional[str]) -> str:
    return repo or DEFAULT_REPO

def _get_headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "backup-github-module",
    }

def _api_get_file(repo: str, path: str, branch: str, token: str) -> Optional[dict]:
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}"
    params = {"ref": branch}
    r = requests.get(url, headers=_get_headers(token), params=params, timeout=30)
    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return None
    r.raise_for_status()

# ---------- Public functions ----------
def push_db_to_github(db_path: Optional[str] = None, repo: Optional[str] = None,
                      path: Optional[str] = None, token: Optional[str] = None,
                      branch: Optional[str] = None, message: Optional[str] = None) -> bool:
    """
    Upload local db file to GitHub (create or update file).
    Raises exceptions on unrecoverable failure.
    Returns True on success.
    """
    db_path = db_path or DEFAULT_LOCAL_DB
    repo = _get_repo_arg(repo)
    path = path or DEFAULT_PATH
    branch = branch or DEFAULT_BRANCH
    token = _get_env_token(token)

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Local DB file not found: {db_path}")
    if not repo:
        raise ValueError("GITHUB_REPO not set (owner/repo)")

    # Try GitHub API first
    if token:
        logger.info("Pushing %s -> %s:%s (branch=%s) via GitHub API", db_path, repo, path, branch)
        with open(db_path, "rb") as f:
            data = f.read()
        content_b64 = base64.b64encode(data).decode("utf-8")
        message = message or f"Backup DB: {os.path.basename(db_path)} (automated)"
        # Check if file exists to include sha for update
        file_info = _api_get_file(repo, path, branch, token)
        payload = {
            "message": message,
            "content": content_b64,
            "branch": branch,
            "committer": {"name": DEFAULT_COMMIT_NAME, "email": DEFAULT_COMMIT_EMAIL},
        }
        if file_info and isinstance(file_info, dict) and file_info.get("sha"):
            payload["sha"] = file_info["sha"]

        url = f"{GITHUB_API}/repos/{repo}/contents/{path}"
        r = requests.put(url, headers=_get_headers(token), data=json.dumps(payload), timeout=60)
        if r.status_code in (200, 201):
            logger.info("Backup pushed successfully to GitHub (status=%s)", r.status_code)
            return True
        else:
            # Log details and raise for caller to handle fallback if desired
            logger.error("GitHub API push failed: status=%s body=%s", r.status_code, r.text)
            r.raise_for_status()

    # If token not provided or API attempt failed and git fallback requested, try git CLI fallback
    if USE_GIT_FALLBACK:
        logger.info("Attempting git CLI fallback push (GITHUB_USE_GIT=1)")
        try:
            return _git_cli_push(db_path, repo, path, branch, message)
        except Exception:
            logger.exception("Git CLI fallback failed")
            raise

    raise RuntimeError("No method succeeded to push DB to GitHub (ensure GITHUB_TOKEN and GITHUB_REPO are set)")

def restore_db_from_github(db_path: Optional[str] = None, repo: Optional[str] = None,
                           path: Optional[str] = None, token: Optional[str] = None,
                           branch: Optional[str] = None) -> bool:
    """
    Download file from GitHub repo and overwrite local db_path.
    Returns True on success. Raises on failure.
    """
    db_path = db_path or DEFAULT_LOCAL_DB
    repo = _get_repo_arg(repo)
    path = path or DEFAULT_PATH
    branch = branch or DEFAULT_BRANCH
    token = _get_env_token(token)

    if not repo:
        raise ValueError("GITHUB_REPO not set (owner/repo)")

    # Prefer API
    if token:
        logger.info("Restoring %s from %s:%s (branch=%s) via GitHub API", db_path, repo, path, branch)
        file_info = _api_get_file(repo, path, branch, token)
        if not file_info:
            raise FileNotFoundError(f"No file at {repo}/{path} on branch {branch}")
        # content may be base64 (for files <=100MB)
        content_b64 = file_info.get("content", "")
        if not content_b64:
            raise RuntimeError("No content found in GitHub response")
        # remove possible newlines and decode
        content_b64_clean = "".join(content_b64.splitlines())
        data = base64.b64decode(content_b64_clean)
        # Write atomically
        tmp = db_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, db_path)
        logger.info("Restored DB to %s", db_path)
        return True

    # If no token and git fallback allowed, try git CLI fallback
    if USE_GIT_FALLBACK:
        logger.info("Attempting git CLI fallback restore (GITHUB_USE_GIT=1)")
        try:
            return _git_cli_pull(db_path, repo, path, branch)
        except Exception:
            logger.exception("Git CLI fallback restore failed")
            raise

    raise RuntimeError("No method available to restore DB from GitHub (set GITHUB_TOKEN or enable GITHUB_USE_GIT)")

# ---------- Optional git CLI fallback ----------
def _git_cli_push(local_file: str, repo: str, path_in_repo: str, branch: str, message: Optional[str]) -> bool:
    """
    Fallback that clones the repo to a temp dir, copies the file in, commits and pushes.
    Requires git and network access from the machine and that GITHUB_TOKEN is available in env for auth.
    This is less efficient but useful if API isn't usable for some reason.
    """
    token = _get_env_token(None)
    if not token:
        raise RuntimeError("GIT CLI fallback requires GITHUB_TOKEN in env")
    tmp_dir = None
    try:
        tmp_dir = shutil.mkdtemp(prefix="backup_git_")
        logger.info("Cloning repo %s into %s", repo, tmp_dir)
        # Use token in URL to avoid interactive auth (be careful with logs)
        remote = f"https://{token}@github.com/{repo}.git"
        subprocess.check_call(["git", "clone", "--depth", "1", "--branch", branch, remote, tmp_dir])
        dest_path = os.path.join(tmp_dir, path_in_repo)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(local_file, dest_path)
        # commit & push
        subprocess.check_call(["git", "-C", tmp_dir, "add", path_in_repo])
        commit_msg = message or f"Backup DB: {os.path.basename(local_file)} (automated)"
        subprocess.check_call(["git", "-C", tmp_dir, "commit", "-m", commit_msg, "--author", f"{DEFAULT_COMMIT_NAME} <{DEFAULT_COMMIT_EMAIL}>"])
        subprocess.check_call(["git", "-C", tmp_dir, "push", "origin", branch])
        logger.info("Git CLI push completed")
        return True
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

def _git_cli_pull(local_file: str, repo: str, path_in_repo: str, branch: str) -> bool:
    token = _get_env_token(None)
    if not token:
        raise RuntimeError("GIT CLI fallback requires GITHUB_TOKEN in env")
    tmp_dir = None
    try:
        tmp_dir = shutil.mkdtemp(prefix="backup_git_")
        remote = f"https://{token}@github.com/{repo}.git"
        subprocess.check_call(["git", "clone", "--depth", "1", "--branch", branch, remote, tmp_dir])
        src_path = os.path.join(tmp_dir, path_in_repo)
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"{path_in_repo} not found in cloned repo")
        os.makedirs(os.path.dirname(local_file), exist_ok=True)
        shutil.copy2(src_path, local_file)
        logger.info("Git CLI pull completed and file copied to %s", local_file)
        return True
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

# ---------- If used directly for quick testing ----------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Push/restore DB to/from GitHub")
    parser.add_argument("--push", action="store_true", help="Push local DB to GitHub")
    parser.add_argument("--restore", action="store_true", help="Restore DB from GitHub")
    parser.add_argument("--db", type=str, help="Local DB path (overrides LOCAL_DB_PATH)")
    parser.add_argument("--repo", type=str, help="GitHub repo (owner/repo)")
    parser.add_argument("--path", type=str, help="Target path in repo")
    parser.add_argument("--branch", type=str, help="Branch name")
    args = parser.parse_args()

    try:
        if args.push:
            push_db_to_github(db_path=args.db, repo=args.repo, path=args.path, branch=args.branch)
        elif args.restore:
            restore_db_from_github(db_path=args.db, repo=args.repo, path=args.path, branch=args.branch)
        else:
            parser.print_help()
    except Exception as e:
        logger.exception("Operation failed: %s", e)
        raise
