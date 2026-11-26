"""Firebase integration: Authentication (REST), Firestore and Storage (Admin SDK).

All Firebase access happens on the Flask backend. The browser never talks to
Firebase directly, so Firestore/Storage rules can be set to "deny all" for
clients and every request is authorised by Flask first.
"""
import os
import re
import uuid
from datetime import datetime, timezone

import firebase_admin
import requests
from firebase_admin import credentials, firestore, storage

_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"

_db = None
_bucket = None
_init_error = None


# --------------------------------------------------------------------------- #
# Initialisation
# --------------------------------------------------------------------------- #
def init_firebase():
    global _db, _bucket, _init_error
    if firebase_admin._apps:
        _db = firestore.client()
        _bucket = storage.bucket()
        return True
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    bucket_name = os.environ.get("FIREBASE_STORAGE_BUCKET")
    if not cred_path or not os.path.exists(cred_path):
        _init_error = "Set GOOGLE_APPLICATION_CREDENTIALS to your service-account JSON path."
        return False
    if not bucket_name:
        _init_error = "Set FIREBASE_STORAGE_BUCKET (e.g. my-project.appspot.com)."
        return False
    try:
        firebase_admin.initialize_app(credentials.Certificate(cred_path),
                                      {"storageBucket": bucket_name})
        _db = firestore.client()
        _bucket = storage.bucket()
        _init_error = None
        return True
    except Exception as exc:
        _init_error = f"Firebase initialization failed: {exc}"
        return False


def db():
    if _db is None:
        raise RuntimeError(_init_error or "Firebase is not initialized.")
    return _db


def bucket():
    if _bucket is None:
        raise RuntimeError(_init_error or "Firebase is not initialized.")
    return _bucket


def now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Firebase Authentication (Email + Password) through the official REST API
# Firebase stores only salted password hashes; this app never sees them stored.
# --------------------------------------------------------------------------- #
class AuthError(Exception):
    pass


_ERRORS = {
    "EMAIL_EXISTS": "An account with this email already exists.",
    "INVALID_LOGIN_CREDENTIALS": "Incorrect email or password.",
    "INVALID_PASSWORD": "Incorrect email or password.",
    "EMAIL_NOT_FOUND": "Incorrect email or password.",
    "USER_DISABLED": "This account has been disabled.",
    "INVALID_EMAIL": "Please enter a valid email address.",
    "WEAK_PASSWORD": "Password is too weak (minimum 8 characters).",
    "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Please try again later.",
}


def _auth_call(endpoint, payload):
    key = os.environ.get("FIREBASE_WEB_API_KEY")
    if not key:
        raise AuthError("Server is missing FIREBASE_WEB_API_KEY.")
    try:
        r = requests.post(f"{_AUTH_URL}:{endpoint}", params={"key": key},
                          json=payload, timeout=15)
    except requests.RequestException:
        raise AuthError("Could not reach Firebase. Check your internet connection.")
    data = r.json()
    if r.status_code != 200:
        code = data.get("error", {}).get("message", "")
        code = code.split(" ")[0]
        raise AuthError(_ERRORS.get(code, "Authentication failed. Please try again."))
    return data


def auth_sign_up(email, password):
    return _auth_call("signUp", {"email": email, "password": password,
                                 "returnSecureToken": True})


def auth_sign_in(email, password):
    return _auth_call("signInWithPassword", {"email": email, "password": password,
                                             "returnSecureToken": True})


def auth_send_reset(email):
    return _auth_call("sendOobCode", {"requestType": "PASSWORD_RESET", "email": email})


def auth_change_password(id_token, new_password):
    return _auth_call("update", {"idToken": id_token, "password": new_password,
                                 "returnSecureToken": False})


# --------------------------------------------------------------------------- #
# Firestore helpers
# --------------------------------------------------------------------------- #
def create_user_profile(uid, full_name, email):
    db().collection("users").document(uid).set({
        "user_id": uid, "full_name": full_name, "email": email, "created_at": now(),
    })


def get_user_profile(uid):
    snap = db().collection("users").document(uid).get()
    return snap.to_dict() if snap.exists else None


def log_activity(uid, file_id, activity_type, file_name=""):
    """activity_type: uploaded | downloaded | deleted"""
    aid = uuid.uuid4().hex
    db().collection("activity").document(aid).set({
        "activity_id": aid, "user_id": uid, "file_id": file_id,
        "activity_type": activity_type, "file_name": file_name, "timestamp": now(),
    })


def list_files(uid):
    docs = db().collection("files").where("user_id", "==", uid).stream()
    items = [d.to_dict() for d in docs]
    items.sort(key=lambda f: f.get("upload_date"), reverse=True)
    return items


def get_file(uid, file_id):
    """Return the file doc ONLY if it belongs to uid (authorisation check)."""
    if not re.fullmatch(r"[0-9a-f]{32}", file_id or ""):
        return None
    snap = db().collection("files").document(file_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    return data if data.get("user_id") == uid else None


def list_activity(uid, limit=None):
    docs = db().collection("activity").where("user_id", "==", uid).stream()
    items = [d.to_dict() for d in docs]
    items.sort(key=lambda a: a.get("timestamp"), reverse=True)
    return items[:limit] if limit else items
