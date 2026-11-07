import os
import sys
import json
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("MCS_Security")

def get_app_dir():
    """Returns directory containing script or executable."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

PASSKEY_FILE = os.path.join(get_app_dir(), ".passkey")

def derive_key(passkey: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from passkey and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(passkey.encode("utf-8"))

def encrypt_accounts_data(accounts_list: list, passkey: str) -> dict:
    """
    Encrypts accounts list using AES-256-GCM.
    Returns a dictionary envelope with base64 encoded salt, nonce, and ciphertext.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passkey, salt)

    aesgcm = AESGCM(key)
    plaintext = json.dumps(accounts_list, indent=2).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    envelope = {
        "format": "MCS_AES256_GCM_V1",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }
    return envelope

def decrypt_accounts_data(envelope: dict, passkey: str) -> list:
    """
    Decrypts accounts list from envelope using passkey.
    Raises ValueError on invalid passkey or corrupted data.
    """
    if not isinstance(envelope, dict) or envelope.get("format") != "MCS_AES256_GCM_V1":
        raise ValueError("Invalid encrypted accounts format")

    try:
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except Exception as e:
        raise ValueError(f"Malformed envelope data: {e}")

    key = derive_key(passkey, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise ValueError("Decryption failed: Incorrect passkey or corrupted ciphertext")

def export_encrypted_pool(accounts_json_path: str, output_enc_path: str, passkey: str):
    """Reads plaintext accounts.json, encrypts it, and writes to accounts.enc."""
    with open(accounts_json_path, "r", encoding="utf-8") as f:
        accounts = json.load(f)

    # Sanitize dynamic run-time state before exporting
    clean_pool = []
    for acc in accounts:
        clean_item = {
            "id": acc.get("id"),
            "sc": acc.get("sc", ""),
            "name": acc.get("name", ""),
            "username": acc.get("username", ""),
            "password": acc.get("password", ""),
            "status": "available"
        }
        clean_pool.append(clean_item)

    envelope = encrypt_accounts_data(clean_pool, passkey)
    with open(output_enc_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    logger.info(f"Encrypted {len(clean_pool)} accounts into {output_enc_path}")
    return len(clean_pool)

def import_encrypted_pool(input_enc_path: str, passkey: str) -> list:
    """Reads accounts.enc, decrypts it using passkey, and returns accounts list."""
    with open(input_enc_path, "r", encoding="utf-8") as f:
        envelope = json.load(f)
    return decrypt_accounts_data(envelope, passkey)

def save_local_passkey(passkey: str):
    """Saves passkey locally so user/friend does not have to enter it repeatedly."""
    try:
        with open(PASSKEY_FILE, "w", encoding="utf-8") as f:
            f.write(passkey.strip())
        # Restrict file attribute on Windows if possible
        if sys.platform == "win32":
            import subprocess
            subprocess.run(["attrib", "+H", PASSKEY_FILE], capture_output=True)
    except Exception as e:
        logger.warning(f"Could not save local passkey file: {e}")

def get_local_passkey() -> str:
    """Retrieves saved local passkey if present, or returns empty string."""
    if os.path.exists(PASSKEY_FILE):
        try:
            with open(PASSKEY_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""
