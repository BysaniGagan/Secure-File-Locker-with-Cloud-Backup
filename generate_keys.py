"""Prints fresh random secrets to paste into your .env file."""
import base64
import os
import secrets

print("SECRET_KEY=" + secrets.token_hex(32))
print("FILE_ENCRYPTION_KEY=" + base64.urlsafe_b64encode(os.urandom(32)).decode())
print("\nKeep these private. If you lose FILE_ENCRYPTION_KEY, encrypted files cannot be recovered.")
