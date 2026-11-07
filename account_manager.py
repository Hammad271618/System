import json
import os
import sys
import logging
import random
from datetime import datetime, date

logger = logging.getLogger("MCS_AccountManager")

def get_app_dir():
    """Returns directory containing script or executable."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

class AccountManager:
    def __init__(self, filepath=None):
        if filepath is None:
            filepath = os.path.join(get_app_dir(), "accounts.json")
        self.filepath = os.path.abspath(filepath)
        self.accounts = []
        self.current_index = -1
        self.last_reset_date = date.today().isoformat()
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            # Check if accounts.enc exists nearby for first-run unlock
            enc_path = os.path.join(os.path.dirname(self.filepath), "accounts.enc")
            if os.path.exists(enc_path):
                try:
                    from security import import_encrypted_pool, get_local_passkey, save_local_passkey
                    passkey = get_local_passkey()
                    if not passkey and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                        try:
                            passkey = input("Enter hostel passkey to unlock student accounts: ").strip()
                        except Exception:
                            passkey = ""
                    if passkey:
                        decrypted = import_encrypted_pool(enc_path, passkey)
                        with open(self.filepath, "w", encoding="utf-8") as f:
                            json.dump(decrypted, f, indent=2)
                        save_local_passkey(passkey)
                        logger.info("Successfully unlocked accounts from accounts.enc")
                except Exception as e:
                    logger.warning(f"Could not automatically unlock accounts.enc: {e}")

        if not os.path.exists(self.filepath):
            logger.error(f"Accounts file {self.filepath} not found!")
            self.accounts = []
            return

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                self.accounts = json.load(f)
            logger.info(f"Loaded {len(self.accounts)} accounts from {self.filepath}")
            
            # Find current or pick random available account
            for idx, acc in enumerate(self.accounts):
                if acc.get("status") == "in_use":
                    self.current_index = idx
                    break
            if self.current_index == -1:
                available_indices = [idx for idx, acc in enumerate(self.accounts) if acc.get("status") == "available"]
                if available_indices:
                    self.current_index = random.choice(available_indices)
                    self.accounts[self.current_index]["status"] = "in_use"
                    self.save()
        except Exception as e:
            logger.error(f"Failed to load accounts: {e}")

    def save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.accounts, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save accounts: {e}")

    def check_daily_reset(self):
        """Resets all accounts to available if a new day has arrived."""
        today = date.today().isoformat()
        if today != self.last_reset_date:
            logger.info(f"New day detected ({today}). Resetting all account quotas!")
            self.reset_all_accounts()
            self.last_reset_date = today

    def reset_all_accounts(self):
        """Reset all accounts to available status and pick a random starting account."""
        for acc in self.accounts:
            acc["status"] = "available"
            acc.pop("exhausted_at", None)
            acc.pop("error_reason", None)
        if self.accounts:
            self.current_index = random.randint(0, len(self.accounts) - 1)
            self.accounts[self.current_index]["status"] = "in_use"
        else:
            self.current_index = -1
        self.save()
        logger.info("All accounts have been reset to 'available'.")

    def get_current_account(self):
        self.check_daily_reset()
        if 0 <= self.current_index < len(self.accounts):
            return self.accounts[self.current_index]
        return self.get_next_account()

    def get_next_account(self):
        """Finds and switches to a random available account in the pool (no fixed sequence)."""
        self.check_daily_reset()
        
        # Mark current as not in_use if it was in_use
        if 0 <= self.current_index < len(self.accounts):
            if self.accounts[self.current_index].get("status") == "in_use":
                self.accounts[self.current_index]["status"] = "available"

        available_indices = [
            i for i, acc in enumerate(self.accounts) 
            if acc.get("status") == "available"
        ]

        if not available_indices:
            logger.warning("No available accounts left! All are exhausted or invalid.")
            self.current_index = -1
            self.save()
            return None

        # Choose randomly among available accounts, avoiding the same account if others exist
        candidates = [i for i in available_indices if i != self.current_index]
        if candidates:
            self.current_index = random.choice(candidates)
        else:
            self.current_index = available_indices[0]

        acc = self.accounts[self.current_index]
        acc["status"] = "in_use"
        acc["last_used"] = datetime.now().isoformat()
        self.save()
        logger.info(f"Switched randomly to account ID #{acc['id']}: {acc['username']} ({acc['name']})")
        return acc

    def mark_current_exhausted(self, reason="Quota reached / Limit hit"):
        """Marks the active account as exhausted (limit reached)."""
        if 0 <= self.current_index < len(self.accounts):
            acc = self.accounts[self.current_index]
            acc["status"] = "exhausted"
            acc["exhausted_at"] = datetime.now().isoformat()
            acc["error_reason"] = reason
            logger.warning(f"Marked account #{acc['id']} ({acc['username']}) as EXHAUSTED: {reason}")
            self.save()

    def mark_current_invalid(self, reason="Invalid credentials / auth rejected"):
        """Marks current account as invalid (e.g. password changed)."""
        if 0 <= self.current_index < len(self.accounts):
            acc = self.accounts[self.current_index]
            acc["status"] = "invalid"
            acc["error_reason"] = reason
            logger.error(f"Marked account #{acc['id']} ({acc['username']}) as INVALID: {reason}")
            self.save()

    def restore_accounts(self, account_ids):
        """Restores specified account IDs back to 'available' after a transient portal/network-wide failure."""
        if not account_ids:
            return
        id_set = set(account_ids)
        restored = 0
        for idx, acc in enumerate(self.accounts):
            if acc.get("id") in id_set and acc.get("status") in ("exhausted", "invalid"):
                acc["status"] = "in_use" if idx == self.current_index else "available"
                acc.pop("exhausted_at", None)
                acc.pop("error_reason", None)
                restored += 1
        if restored:
            self.save()
            logger.info(f"Restored {restored} accounts back to 'available' after full-cycle portal failure.")

    def get_stats(self):
        total = len(self.accounts)
        available = sum(1 for a in self.accounts if a.get("status") == "available")
        in_use = sum(1 for a in self.accounts if a.get("status") == "in_use")
        exhausted = sum(1 for a in self.accounts if a.get("status") == "exhausted")
        invalid = sum(1 for a in self.accounts if a.get("status") == "invalid")
        current_user = self.accounts[self.current_index]["username"] if (0 <= self.current_index < total) else "None"
        return {
            "total": total,
            "available": available + in_use,
            "exhausted": exhausted,
            "invalid": invalid,
            "current_index": self.current_index + 1 if self.current_index >= 0 else 0,
            "current_user": current_user
        }

    def get_account_by_id(self, account_id):
        """Finds and returns an account dict by its numeric ID, or None."""
        try:
            target_id = int(account_id)
        except (ValueError, TypeError):
            return None
        for acc in self.accounts:
            if acc.get("id") == target_id:
                return acc
        return None

    def set_current_account_by_id(self, account_id):
        """Switches active account to the specified ID."""
        try:
            target_id = int(account_id)
        except (ValueError, TypeError):
            return False

        found_idx = -1
        for idx, acc in enumerate(self.accounts):
            if acc.get("id") == target_id:
                found_idx = idx
                break

        if found_idx == -1:
            return False

        # Clear previous in_use if applicable
        if 0 <= self.current_index < len(self.accounts) and self.current_index != found_idx:
            if self.accounts[self.current_index].get("status") == "in_use":
                self.accounts[self.current_index]["status"] = "available"

        self.current_index = found_idx
        acc = self.accounts[self.current_index]
        acc["status"] = "in_use"
        acc["last_used"] = datetime.now().isoformat()
        self.save()
        logger.info(f"Switched active account to ID #{acc['id']} ({acc['username']})")
        return True

    def add_account(self, username, password, name="", sc=""):
        """Adds a new account to the pool and saves to accounts.json."""
        username = (username or "").strip()
        password = (password or "").strip()
        if not username or not password:
            raise ValueError("Username and password cannot be empty")

        new_id = max([a.get("id", 0) for a in self.accounts], default=0) + 1
        new_acc = {
            "id": new_id,
            "sc": str(sc).strip() if sc else "",
            "name": str(name).strip().upper() if name else username.split(".")[0].upper(),
            "username": username,
            "password": password,
            "status": "available"
        }
        self.accounts.append(new_acc)
        self.save()
        logger.info(f"Added new account #{new_id}: {username}")
        return new_acc

    def remove_account(self, account_id):
        """Removes an account by ID."""
        try:
            target_id = int(account_id)
        except (ValueError, TypeError):
            return False

        initial_len = len(self.accounts)
        self.accounts = [a for a in self.accounts if a.get("id") != target_id]
        if len(self.accounts) < initial_len:
            # Re-sync current_index
            self.current_index = -1
            for idx, acc in enumerate(self.accounts):
                if acc.get("status") == "in_use":
                    self.current_index = idx
                    break
            if self.current_index == -1:
                for idx, acc in enumerate(self.accounts):
                    if acc.get("status") == "available":
                        self.current_index = idx
                        break
            self.save()
            logger.info(f"Removed account ID #{target_id}")
            return True
        return False
