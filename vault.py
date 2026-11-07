"""Core auth, crypto, and file-storage logic for the vault app.

Extracted out of the notebooks so it can be unit tested and reused by
both the CLI and GUI menus instead of being duplicated in each.
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet

USERS_FILE = "users.txt"
USERS_DIR = "users"

PBKDF2_ITERATIONS = 200_000


def _pbkdf2(password, salt, dklen=None):
    kwargs = {} if dklen is None else {"dklen": dklen}
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, **kwargs)


def hash_password(password, salt):
    """Salted password hash, hex-encoded for storage."""
    return _pbkdf2(password, salt).hex()


def verify_password(password, salt, expected_hash):
    return hash_password(password, salt) == expected_hash


def derive_file_key(password, salt):
    """Derive this user's Fernet key from their password + salt.

    Each user's files are encrypted with a key tied to their own
    password, instead of one Fernet key shared by every account.
    """
    raw = _pbkdf2(password, salt, dklen=32)
    return base64.urlsafe_b64encode(raw)


def save_user_credentials(username, salt, hashed_pw):
    with open(USERS_FILE, "a") as file:
        file.write(username + ":" + salt.hex() + ":" + hashed_pw + "\n")


def get_user_record(username):
    if not os.path.exists(USERS_FILE):
        return None

    with open(USERS_FILE, "r") as file:
        lines = file.readlines()

    for line in lines:
        parts = line.strip().split(":")
        if len(parts) == 3 and parts[0] == username:
            return {"username": parts[0], "salt": bytes.fromhex(parts[1]), "hash": parts[2]}

    return None


def check_user(username):
    return get_user_record(username) is not None


def register(username, password):
    """Create a new user. Returns their derived file key."""
    if check_user(username):
        raise ValueError("User already exists")

    salt = os.urandom(16)
    hashed = hash_password(password, salt)
    save_user_credentials(username, salt, hashed)
    make_user_folder(username)

    return derive_file_key(password, salt)


def login(username, password):
    """Returns (True, file_key) on success, (False, None) on failure."""
    record = get_user_record(username)
    if record is None:
        return False, None

    if not verify_password(password, record["salt"], record["hash"]):
        return False, None

    return True, derive_file_key(password, record["salt"])


def make_user_folder(username):
    folder = os.path.join(USERS_DIR, username, "files")
    os.makedirs(folder, exist_ok=True)
    return folder


def user_folder(username):
    return os.path.join(USERS_DIR, username, "files")


def encrypt(data, key):
    return Fernet(key).encrypt(data)


def decrypt(token, key):
    return Fernet(key).decrypt(token)


def save_encrypted_file(username, fname, token):
    folder = make_user_folder(username)
    path = os.path.join(folder, fname)
    with open(path, "wb") as file:
        file.write(token)


def load_encrypted_file(username, fname):
    path = os.path.join(user_folder(username), fname)
    with open(path, "rb") as file:
        return file.read()


def delete_file(username, fname):
    path = os.path.join(user_folder(username), fname)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def list_files(username):
    folder = user_folder(username)
    if not os.path.exists(folder):
        return []
    return os.listdir(folder)
