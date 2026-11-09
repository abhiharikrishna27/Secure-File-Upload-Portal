from flask import (
    Flask, render_template, request,
    send_from_directory, abort, session,
    redirect, url_for
)

from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from pathlib import Path
from PIL import Image
from pypdf import PdfReader
from pypdf.generic import IndirectObject, DictionaryObject, ArrayObject
from io import BytesIO
from datetime import datetime, timedelta
import sqlite3
import uuid
import os
import unicodedata


app = Flask(__name__)

# Session configuration
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "secure-file-portal-local-development-key-change-before-deployment"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() == "true"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# Maximum upload size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Admin credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")

ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASSWORD", "Admin@123")
)

# Allowed file types
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}

# Private upload storage outside the Flask project folder
UPLOAD_FOLDER = (
    Path(app.root_path).parent /
    "secure_file_portal_private_uploads"
)

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

# Database remains inside the project folder
DATABASE = Path(app.root_path) / "uploads.db"


# Get current date and time
def current_time():
    return datetime.now().strftime("%d-%m-%Y %I:%M %p")


# Filename validation and normalization
def validate_filename(filename):
    """
    Normalize and validate the uploaded filename.
    Returns a safe filename or raises ValueError.
    """

    if not filename:
        raise ValueError("Filename is empty.")

    filename = unicodedata.normalize("NFKC", filename)

    filename = filename.replace("\\", "/")
    filename = filename.split("/")[-1]

    filename = "".join(
        character
        for character in filename
        if unicodedata.category(character)[0] != "C"
    )

    filename = filename.strip()

    if not filename:
        raise ValueError("Filename is empty or invalid.")

    if len(filename) > 255:
        raise ValueError("Filename is too long.")

    if filename in {".", ".."}:
        raise ValueError("Invalid filename.")

    safe_name = secure_filename(filename)

    if not safe_name:
        raise ValueError("Filename contains invalid characters.")

    extension = Path(safe_name).suffix.lower()

    if not extension:
        raise ValueError("Filename has no extension.")

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("File extension is not allowed.")

    return safe_name


# Security logging
def log_security_event(filename, status, reason):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            INSERT INTO security_logs
            (filename, status, reason, event_time)
            VALUES (?, ?, ?, ?)
        """, (filename, status, reason, current_time()))


# Initialize database
def init_db():
    with sqlite3.connect(DATABASE) as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_filename TEXT,
                stored_filename TEXT,
                file_type TEXT,
                file_size INTEGER,
                uploaded_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                status TEXT,
                reason TEXT,
                event_time TEXT
            )
        """)


init_db()


# Get upload history
def get_upload_history():
    with sqlite3.connect(DATABASE) as conn:
        return conn.execute("""
            SELECT id, original_filename, file_type,
                   file_size, uploaded_at
            FROM uploads
            ORDER BY id DESC
        """).fetchall()


# Check PDF for potentially dangerous content
def contains_active_pdf_content(pdf_object):

    dangerous_keys = {
        "/JavaScript", "/JS", "/OpenAction", "/AA",
        "/Launch", "/SubmitForm", "/ImportData", "/GoToR"
    }

    dangerous_actions = {
        "/JavaScript", "/Launch", "/SubmitForm",
        "/ImportData", "/GoToR"
    }

    objects_to_check = [pdf_object]
    visited = set()

    while objects_to_check:

        obj = objects_to_check.pop()

        if isinstance(obj, IndirectObject):

            object_id = (obj.idnum, obj.generation)

            if object_id in visited:
                continue

            visited.add(object_id)
            obj = obj.get_object()

        else:

            object_id = id(obj)

            if object_id in visited:
                continue

            visited.add(object_id)

        if isinstance(obj, DictionaryObject):

            for key, value in obj.items():

                key_name = str(key)

                if key_name in dangerous_keys:
                    return True

                if key_name == "/S" and str(value) in dangerous_actions:
                    return True

                objects_to_check.append(value)

        elif isinstance(obj, ArrayObject):
            objects_to_check.extend(obj)

    return False


# Home page and file upload
@app.route("/", methods=["GET", "POST"])
def home():

    message = ""
    success = False

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:

            message = "Please select a file."

            log_security_event(
                "No file selected",
                "REJECTED",
                message
            )

        else:

            original_name = uploaded_file.filename

            safe_name = None
            safe_filename = None

            try:

                safe_name = validate_filename(original_name)

                extension = Path(safe_name).suffix.lower()

                # Image validation
                if extension in IMAGE_EXTENSIONS:

                    expected_formats = {
                        ".jpg": "JPEG",
                        ".jpeg": "JPEG",
                        ".png": "PNG"
                    }

                    uploaded_file.stream.seek(0)

                    with Image.open(uploaded_file.stream) as image:

                        if image.format != expected_formats[extension]:
                            raise ValueError("Image format mismatch.")

                        image.verify()

                # PDF validation
                elif extension == ".pdf":

                    uploaded_file.stream.seek(0)
                    pdf_bytes = uploaded_file.stream.read()

                    if not pdf_bytes.startswith(b"%PDF-"):
                        raise ValueError("Invalid PDF signature.")

                    reader = PdfReader(
                        BytesIO(pdf_bytes),
                        strict=True
                    )

                    if reader.is_encrypted:
                        raise ValueError("Encrypted PDF.")

                    len(reader.pages)

                    if contains_active_pdf_content(reader.trailer):
                        raise ValueError(
                            "Potentially dangerous PDF content."
                        )

                # Generate unique filename
                uploaded_file.stream.seek(0)

                safe_filename = f"{uuid.uuid4().hex}{extension}"

                # Save in private storage folder
                upload_path = UPLOAD_FOLDER / safe_filename

                uploaded_file.save(upload_path)

                file_size = upload_path.stat().st_size

                # Save upload details in database
                with sqlite3.connect(DATABASE) as conn:

                    conn.execute("""
                        INSERT INTO uploads (
                            original_filename,
                            stored_filename,
                            file_type,
                            file_size,
                            uploaded_at
                        )
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        safe_name,
                        safe_filename,
                        extension,
                        file_size,
                        current_time()
                    ))

                message = "File validated and uploaded successfully!"
                success = True

                log_security_event(
                    safe_name,
                    "ACCEPTED",
                    "File passed validation and was uploaded."
                )

            except Exception as error:

                if safe_filename:

                    saved_file = UPLOAD_FOLDER / safe_filename

                    if saved_file.exists():
                        saved_file.unlink()

                if isinstance(error, ValueError):
                    reason = str(error)
                else:
                    reason = "Invalid, damaged, or unreadable file."

                message = (
                    "Rejected: invalid, damaged, or potentially "
                    "dangerous file."
                )

                log_security_event(
                    original_name,
                    "REJECTED",
                    reason
                )

    history = get_upload_history()

    return render_template(
        "index.html",
        message=message,
        success=success,
        history=history,
        admin_logged_in=session.get("admin_logged_in", False)
    )


# Admin login
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            username == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, password)
        ):

            session.clear()
            session.permanent = True
            session["admin_logged_in"] = True

            return redirect(url_for("admin"))

        message = "Invalid username or password."

        log_security_event(
            "Admin login",
            "REJECTED",
            "Failed admin login attempt."
        )

    return render_template(
        "admin_login.html",
        message=message
    )


# Admin logout
@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(url_for("admin_login"))


# Admin dashboard
@app.route("/admin")
def admin():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    with sqlite3.connect(DATABASE) as conn:

        total = conn.execute(
            "SELECT COUNT(*) FROM uploads"
        ).fetchone()[0]

        pdf_count = conn.execute(
            "SELECT COUNT(*) FROM uploads WHERE file_type = '.pdf'"
        ).fetchone()[0]

        image_count = conn.execute("""
            SELECT COUNT(*) FROM uploads
            WHERE file_type IN ('.jpg', '.jpeg', '.png')
        """).fetchone()[0]

        total_size = conn.execute(
            "SELECT COALESCE(SUM(file_size), 0) FROM uploads"
        ).fetchone()[0]

        history = conn.execute("""
            SELECT id, original_filename, file_type,
                   file_size, uploaded_at
            FROM uploads
            ORDER BY id DESC
        """).fetchall()

        security_logs = conn.execute("""
            SELECT filename, status, reason, event_time
            FROM security_logs
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return render_template(
        "admin.html",
        total=total,
        pdf_count=pdf_count,
        image_count=image_count,
        total_size=round(total_size / 1024, 2),
        history=history,
        security_logs=security_logs
    )


# Protected file download
@app.route("/download/<int:file_id>")
def download_file(file_id):

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    with sqlite3.connect(DATABASE) as conn:

        file_record = conn.execute("""
            SELECT original_filename, stored_filename
            FROM uploads
            WHERE id = ?
        """, (file_id,)).fetchone()

    if not file_record:
        abort(404)

    original_name, stored_name = file_record

    if not stored_name or Path(stored_name).name != stored_name:
        abort(404)

    file_path = UPLOAD_FOLDER / stored_name

    if not file_path.is_file():
        abort(404)

    return send_from_directory(
        str(UPLOAD_FOLDER),
        stored_name,
        as_attachment=True,
        download_name=original_name
    )


# Handle files larger than 5 MB
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):

    log_security_event(
        "Unknown file",
        "REJECTED",
        "File size exceeded the 5 MB limit."
    )

    return render_template(
        "index.html",
        message="Rejected: file size must not exceed 5 MB.",
        success=False,
        history=get_upload_history(),
        admin_logged_in=session.get("admin_logged_in", False)
    ), 413


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )