"""Secure File Locker with Cloud Backup - Flask backend."""
import io
import os
import re
import tempfile
import time
import uuid
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv

load_dotenv()

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.utils import secure_filename

import firebase_service as fb
from crypto_utils import ALGORITHM_NAME, InvalidTag, decrypt_bytes, encrypt_bytes

# --------------------------------------------------------------------------- #
# App configuration
# --------------------------------------------------------------------------- #
app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set. Run `python generate_keys.py` and fill in .env")

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
IS_PROD = os.environ.get("FLASK_ENV", "development") == "production"

app.config.update(
    SECRET_KEY=_secret,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024 + 1024 * 64,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,          # HTTPS only in production
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    WTF_CSRF_TIME_LIMIT=None,
)
csrf = CSRFProtect(app)
fb.init_firebase()

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "png", "jpg", "jpeg", "gif", "webp", "zip", "mp3", "mp4",
}

# Encrypted blobs waiting for cloud upload (step 2 of the upload flow).
PENDING_DIR = os.path.join(tempfile.gettempdir(), "secure_file_locker_pending")
os.makedirs(PENDING_DIR, exist_ok=True)
PENDING = {}
PENDING_TTL = 600  # seconds

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            if request.path.startswith("/api/"):
                return jsonify(error="Please log in again."), 401
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def valid_password(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


@app.template_filter("filesize")
def filesize_filter(n):
    return human_size(n)


@app.template_filter("dt")
def dt_filter(value):
    return value.strftime("%d %b %Y, %H:%M UTC") if value else "-"


@app.context_processor
def inject_globals():
    return {"max_upload_mb": MAX_UPLOAD_MB,
            "allowed_ext": sorted(ALLOWED_EXTENSIONS)}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def cleanup_pending():
    cutoff = time.time() - PENDING_TTL
    for token in [t for t, m in PENDING.items() if m["created"] < cutoff]:
        meta = PENDING.pop(token)
        try:
            os.remove(meta["path"])
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Public pages & authentication
# --------------------------------------------------------------------------- #
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "uid" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm_password", "")
        error = None
        if not (2 <= len(name) <= 80):
            error = "Please enter your full name."
        elif not EMAIL_RE.match(email):
            error = "Please enter a valid email address."
        elif not valid_password(pw):
            error = "Password must be at least 8 characters and include a letter and a number."
        elif pw != pw2:
            error = "Passwords do not match."
        if not error:
            try:
                data = fb.auth_sign_up(email, pw)
                fb.create_user_profile(data["localId"], name, email)
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))
            except fb.AuthError as e:
                error = str(e)
        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "uid" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        try:
            data = fb.auth_sign_in(email, pw)
            uid = data["localId"]
            profile = fb.get_user_profile(uid) or {}
            session.clear()
            session.permanent = True
            session["uid"] = uid
            session["email"] = email
            session["name"] = profile.get("full_name", email.split("@")[0])
            return redirect(url_for("dashboard"))
        except fb.AuthError as e:
            flash(str(e), "error")
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if EMAIL_RE.match(email):
            if not os.environ.get("FIREBASE_WEB_API_KEY", "").strip():
                flash(
                    "Password reset is unavailable. Configure FIREBASE_WEB_API_KEY in .env and restart the app.",
                    "error",
                )
                return redirect(url_for("login"))
            try:
                fb.auth_send_reset(email)
            except fb.AuthError as exc:
                app.logger.warning("Password reset request failed: %s", exc)
        flash("If an account exists for that email, a reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))


# --------------------------------------------------------------------------- #
# Application pages
# --------------------------------------------------------------------------- #
@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["uid"]
    files = fb.list_files(uid)
    total_bytes = sum(f.get("file_size", 0) for f in files)
    all_backed_up = all(f.get("backup_status") == "Completed" for f in files)
    return render_template(
        "dashboard.html", active="dashboard",
        total_files=len(files), total_bytes=total_bytes,
        backup_ok=all_backed_up, activities=fb.list_activity(uid, limit=6),
    )


@app.route("/upload")
@login_required
def upload_page():
    return render_template("upload.html", active="upload")


@app.route("/files")
@login_required
def files_page():
    return render_template("files.html", active="files", files=fb.list_files(session["uid"]))


@app.route("/activity")
@login_required
def activity_page():
    return render_template("activity.html", active="activity",
                           activities=fb.list_activity(session["uid"]))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    uid = session["uid"]
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not valid_password(new):
            flash("New password must be at least 8 characters with a letter and a number.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        else:
            try:
                # Re-authenticate, then change the password in Firebase Auth.
                data = fb.auth_sign_in(session["email"], current)
                fb.auth_change_password(data["idToken"], new)
                flash("Password updated successfully.", "success")
            except fb.AuthError:
                flash("Current password is incorrect.", "error")
        return redirect(url_for("settings"))
    profile = fb.get_user_profile(uid) or {}
    return render_template("settings.html", active="settings", profile=profile)


# --------------------------------------------------------------------------- #
# Upload API  (step 1: encrypt on backend, step 2: back up to Firebase Storage)
# --------------------------------------------------------------------------- #
@app.route("/api/upload/encrypt", methods=["POST"])
@login_required
def api_encrypt():
    cleanup_pending()
    uid = session["uid"]
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="No file selected."), 400

    original = secure_filename(f.filename) or "file"
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify(error=f"File type '.{ext or '?'}' is not allowed."), 400

    data = f.read()
    if not data:
        return jsonify(error="The file is empty."), 400
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        return jsonify(error=f"File exceeds the {MAX_UPLOAD_MB} MB limit."), 413

    file_id = uuid.uuid4().hex
    blob = encrypt_bytes(data, uid, file_id)       # <- encryption happens HERE
    del data                                       # plaintext no longer needed

    token = uuid.uuid4().hex
    path = os.path.join(PENDING_DIR, token + ".enc")
    with open(path, "wb") as out:                  # only ciphertext touches disk
        out.write(blob)
    PENDING[token] = {"uid": uid, "file_id": file_id, "original": original,
                      "size": len(blob), "path": path, "created": time.time()}
    return jsonify(token=token, encrypted_size=len(blob))


@app.route("/api/upload/backup", methods=["POST"])
@login_required
def api_backup():
    uid = session["uid"]
    token = (request.get_json(silent=True) or {}).get("token", "")
    meta = PENDING.get(token)
    if not meta or meta["uid"] != uid:
        return jsonify(error="Upload session expired. Please try again."), 404
    try:
        with open(meta["path"], "rb") as fh:
            blob = fh.read()
        file_id = meta["file_id"]
        cloud_path = f"encrypted/{uid}/{file_id}.enc"
        fb.bucket().blob(cloud_path).upload_from_string(
            blob, content_type="application/octet-stream")

        fb.db().collection("files").document(file_id).set({
            "file_id": file_id, "user_id": uid,
            "original_filename": meta["original"],
            "encrypted_filename": f"{file_id}.enc",
            "file_size": meta["size"],
            "upload_date": fb.now(),
            "cloud_storage_path": cloud_path,
            "encryption_algorithm": ALGORITHM_NAME,
            "backup_status": "Completed",
        })
        fb.log_activity(uid, file_id, "uploaded", meta["original"])
    except Exception:
        app.logger.exception("Cloud upload failed")
        return jsonify(error="Cloud upload failed. Please try again."), 500
    finally:
        PENDING.pop(token, None)
        try:
            os.remove(meta["path"])
        except OSError:
            pass
    return jsonify(ok=True, file_id=file_id)


# --------------------------------------------------------------------------- #
# Download / delete (always authorised against the logged-in user)
# --------------------------------------------------------------------------- #
@app.route("/files/<file_id>/download")
@login_required
def download(file_id):
    uid = session["uid"]
    doc = fb.get_file(uid, file_id)
    if not doc:
        abort(404)
    try:
        blob = fb.bucket().blob(doc["cloud_storage_path"]).download_as_bytes()
    except Exception:
        app.logger.exception("Cloud download failed")
        flash("Could not fetch the file from cloud storage.", "error")
        return redirect(url_for("files_page"))

    name = doc["original_filename"]
    if request.args.get("mode") == "encrypted":         # raw encrypted backup
        fb.log_activity(uid, file_id, "downloaded", name)
        return send_file(io.BytesIO(blob), as_attachment=True,
                         download_name=doc["encrypted_filename"],
                         mimetype="application/octet-stream")
    try:
        plain = decrypt_bytes(blob, uid, file_id)       # verifies GCM integrity tag
    except (InvalidTag, ValueError):
        flash("Integrity check failed: the stored file is corrupted or has been tampered with.", "error")
        return redirect(url_for("files_page"))

    fb.log_activity(uid, file_id, "downloaded", name)
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=name,
                     mimetype="application/octet-stream")


@app.route("/api/files/<file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    uid = session["uid"]
    doc = fb.get_file(uid, file_id)
    if not doc:
        return jsonify(error="File not found."), 404
    try:
        blob = fb.bucket().blob(doc["cloud_storage_path"])
        if blob.exists():
            blob.delete()
        fb.db().collection("files").document(file_id).delete()
        fb.log_activity(uid, file_id, "deleted", doc["original_filename"])
    except Exception:
        app.logger.exception("Delete failed")
        return jsonify(error="Could not delete the file."), 500
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
@app.errorhandler(CSRFError)
def csrf_error(e):
    del e
    if request.path.startswith("/api/"):
        return jsonify(error="Security token expired. Refresh the page."), 400
    flash("Your session expired. Please try again.", "error")
    return redirect(request.referrer or url_for("landing"))


@app.errorhandler(413)
def too_large(e):
    del e
    return jsonify(error=f"File exceeds the {MAX_UPLOAD_MB} MB limit."), 413


@app.errorhandler(404)
def not_found(e):
    del e
    return render_template("error.html", code=404, message="Page or file not found."), 404


if __name__ == "__main__":
    app.run(debug=not IS_PROD)
