"""AES-256-GCM encryption helpers.

Design:
  * One 32-byte MASTER key lives only in the FILE_ENCRYPTION_KEY environment
    variable (never in Firestore / Firebase Storage / source code).
  * A separate 256-bit key is derived per user with HKDF-SHA256, so one
    user's key can never decrypt another user's files.
  * Every encryption uses a fresh random 96-bit nonce (os.urandom).
  * user_id + file_id are bound to the ciphertext as AAD, so an encrypted blob
    cannot be swapped to another file/user without failing authentication.
  * GCM's 128-bit tag verifies integrity: tampering raises InvalidTag.

Blob layout:  MAGIC(4) | NONCE(12) | CIPHERTEXT + TAG
"""
import base64
import os

from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SFL1"
NONCE_SIZE = 12
ALGORITHM_NAME = "AES-256-GCM"

__all__ = ["encrypt_bytes", "decrypt_bytes", "InvalidTag", "ALGORITHM_NAME",
           "generate_master_key"]


def generate_master_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def _master_key() -> bytes:
    raw = os.environ.get("FILE_ENCRYPTION_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "FILE_ENCRYPTION_KEY is not set. Run `python generate_keys.py` "
            "and copy the value into your .env file."
        )
    key = base64.urlsafe_b64decode(raw.encode())
    if len(key) != 32:
        raise RuntimeError("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return key


def _user_key(user_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-file-locker:" + user_id.encode(),
    ).derive(_master_key())


def _aad(user_id: str, file_id: str) -> bytes:
    return f"{user_id}:{file_id}".encode()


def encrypt_bytes(plaintext: bytes, user_id: str, file_id: str) -> bytes:
    nonce = os.urandom(NONCE_SIZE)  # unique for EVERY encryption
    ct = AESGCM(_user_key(user_id)).encrypt(nonce, plaintext, _aad(user_id, file_id))
    return MAGIC + nonce + ct


def decrypt_bytes(blob: bytes, user_id: str, file_id: str) -> bytes:
    """Raises InvalidTag (or ValueError) if the data is corrupt or tampered."""
    if len(blob) < len(MAGIC) + NONCE_SIZE + 16 or not blob.startswith(MAGIC):
        raise ValueError("Not a valid encrypted file.")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    ct = blob[len(MAGIC) + NONCE_SIZE:]
    return AESGCM(_user_key(user_id)).decrypt(nonce, ct, _aad(user_id, file_id))
