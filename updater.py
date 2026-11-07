import os
import sys
import json
import logging
import urllib.request
import urllib.error
from security import (
    decrypt_accounts_data,
    get_local_passkey,
    save_local_passkey,
    get_app_dir
)

logger = logging.getLogger("MCS_Updater")

CURRENT_VERSION = "1.1.0"
DEFAULT_REPO = "Hammad271618/System"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{DEFAULT_REPO}/main"

def check_for_updates(repo: str = DEFAULT_REPO) -> tuple:
    """
    Checks GitHub for newer version of the software.
    Returns: (has_update: bool, remote_version: str, info: dict)
    """
    url = f"https://raw.githubusercontent.com/{repo}/main/version.json"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"System/{CURRENT_VERSION}"}
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                remote_version = data.get("version", CURRENT_VERSION)
                has_update = _is_newer_version(CURRENT_VERSION, remote_version)
                return has_update, remote_version, data
    except Exception as e:
        logger.debug(f"Update check skipped or failed: {e}")

    return False, CURRENT_VERSION, {}

def sync_accounts_from_cloud(passkey: str = None, repo: str = DEFAULT_REPO) -> tuple:
    """
    Fetches encrypted accounts from GitHub, decrypts using passkey,
    and merges new student accounts into local accounts.json.
    Returns: (success: bool, message: str, added_count: int)
    """
    if not passkey:
        passkey = get_local_passkey()

    if not passkey:
        return False, "No passkey provided or saved.", 0

    url = f"https://raw.githubusercontent.com/{repo}/main/accounts.enc"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"System/{CURRENT_VERSION}"}
        )
        with urllib.request.urlopen(req, timeout=8) as res:
            if res.status != 200:
                return False, f"HTTP {res.status} fetching encrypted accounts.", 0
            envelope = json.loads(res.read().decode("utf-8"))
    except Exception as e:
        logger.debug(f"Cloud account fetch error: {e}")
        return False, f"Could not connect to GitHub: {e}", 0

    try:
        cloud_accounts = decrypt_accounts_data(envelope, passkey)
    except Exception as e:
        return False, f"Decryption failed: {e}", 0

    # Save passkey locally for future auto-syncs
    save_local_passkey(passkey)

    # Merge into local accounts.json
    app_dir = get_app_dir()
    local_acc_path = os.path.join(app_dir, "accounts.json")
    local_accounts = []
    if os.path.exists(local_acc_path):
        try:
            with open(local_acc_path, "r", encoding="utf-8") as f:
                local_accounts = json.load(f)
        except Exception:
            local_accounts = []

    local_by_user = {a.get("username"): a for a in local_accounts}
    added_count = 0
    updated_count = 0

    for c_acc in cloud_accounts:
        user = c_acc.get("username")
        if not user:
            continue
        if user not in local_by_user:
            # New account added
            new_id = max([a.get("id", 0) for a in local_accounts], default=0) + 1
            new_entry = {
                "id": new_id,
                "sc": c_acc.get("sc", ""),
                "name": c_acc.get("name", ""),
                "username": user,
                "password": c_acc.get("password", ""),
                "status": "available"
            }
            local_accounts.append(new_entry)
            local_by_user[user] = new_entry
            added_count += 1
        else:
            # Update password or name if modified
            loc = local_by_user[user]
            if c_acc.get("password") and loc.get("password") != c_acc.get("password"):
                loc["password"] = c_acc.get("password")
                updated_count += 1
            if c_acc.get("name") and loc.get("name") != c_acc.get("name"):
                loc["name"] = c_acc.get("name")

    try:
        with open(local_acc_path, "w", encoding="utf-8") as f:
            json.dump(local_accounts, f, indent=2)
    except Exception as e:
        return False, f"Failed to save local accounts: {e}", 0

    msg = f"Synced successfully! Added {added_count} new accounts, updated {updated_count} accounts."
    logger.info(msg)
    return True, msg, added_count

def _is_newer_version(local_ver: str, remote_ver: str) -> bool:
    """Compares semantic version strings e.g. '1.1.0' > '1.0.0'."""
    def parse(v):
        parts = []
        for p in str(v).strip().lstrip("v").split("."):
            if p.isdigit():
                parts.append(int(p))
            else:
                parts.append(0)
        return parts
    return parse(remote_ver) > parse(local_ver)
