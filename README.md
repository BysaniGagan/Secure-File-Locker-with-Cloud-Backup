# Secure File Locker with Cloud Backup

Flask + Firebase (Auth, Firestore, Storage) web app. Files are encrypted with **AES-256-GCM on the Python backend** before they are uploaded; only ciphertext is ever stored in the cloud.

## 1. Project structure

```
secure_file_locker/
├── app.py                 # Flask routes, auth, upload/download/delete APIs
├── crypto_utils.py        # AES-256-GCM (per-user HKDF key, random nonce, AAD)
├── firebase_service.py    # Firebase Auth (REST), Firestore, Storage helpers
├── generate_keys.py       # creates SECRET_KEY + FILE_ENCRYPTION_KEY
├── requirements.txt
├── .env.example           # copy to .env
├── templates/             # 8 pages + shared layouts
└── static/css, static/js
```

## 2. Firebase setup (once)

1. https://console.firebase.google.com → **Add project**.
2. **Build → Authentication → Get started → Email/Password → Enable**.
3. **Build → Firestore Database → Create database** (production mode).
4. **Build → Storage → Get started**. Note the bucket name (e.g. `my-project.appspot.com`).
5. **Project settings → General** → copy the **Web API Key**.
6. **Project settings → Service accounts → Generate new private key** → save the file as `serviceAccountKey.json` in the project folder.
7. Set **deny-all** rules (the browser never talks to Firebase; Flask uses the Admin SDK, which bypasses rules):
   - Firestore rules: `rules_version = '2'; service cloud.firestore { match /databases/{db}/documents { match /{document=**} { allow read, write: if false; } } }`
   - Storage rules: `rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read, write: if false; } } }`

## 3. Run locally in VS Code

```bash
cd secure_file_locker
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python generate_keys.py        # copy output into .env
copy .env.example .env         # then fill in all values (Mac/Linux: cp)
python app.py
```

Open http://127.0.0.1:5000

## 4. Security features (for your viva)

| Requirement | Implementation |
|---|---|
| AES-256-GCM | `crypto_utils.py`, `cryptography` library `AESGCM` |
| Unique nonce | `os.urandom(12)` on every encryption |
| Key management | Master key only in `.env` (`FILE_ENCRYPTION_KEY`); per-user key via HKDF-SHA256; never stored in Firestore/Storage |
| Integrity | GCM tag; `InvalidTag` → "corrupted or tampered" message. `user_id:file_id` is bound as AAD |
| Encrypt before upload | `/api/upload/encrypt` encrypts, then `/api/upload/backup` sends ciphertext only |
| Passwords | Handled by Firebase Authentication (salted hashes); app never stores them |
| Authorization | `login_required` + `get_file()` checks `user_id` on every download/delete |
| CSRF | Flask-WTF `CSRFProtect` (forms + `X-CSRFToken` header on fetch/XHR) |
| Sessions | HttpOnly, SameSite=Lax, Secure in production, 2-hour lifetime |
| Validation | Extension allow-list, size limit (server + client), `secure_filename` |
| Headers | nosniff, X-Frame-Options, HSTS in production |

## 5. Firestore collections

- `users`: user_id, full_name, email, created_at
- `files`: file_id, user_id, original_filename, encrypted_filename, file_size, upload_date, cloud_storage_path, encryption_algorithm, backup_status
- `activity`: activity_id, user_id, file_id, activity_type, timestamp (+ file_name for display after deletion)

## 6. Notes & limits

- **Back up `FILE_ENCRYPTION_KEY`.** If lost, files cannot be decrypted.
- Files are encrypted in memory (default limit 25 MB). Fine for a mini project.
- The temporary encrypted blob between the two upload steps is held in the OS temp folder for at most 10 minutes (ciphertext only), tracked in memory, so run a single server process.
- Production: set `FLASK_ENV=production`, serve behind HTTPS with `gunicorn app:app`, and use a secrets manager (Google Secret Manager, etc.) instead of a `.env` file.
