import os
import sqlite3
from functools import wraps
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------
app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Secret key for sessions
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# Upload directories
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
IMAGE_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, "images")
VIDEO_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, "videos")

os.makedirs(IMAGE_UPLOAD_DIR, exist_ok=True)
os.makedirs(VIDEO_UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "avi", "mov", "mkv"}

# SQLite database for users & cases
DATABASE = os.path.join(BASE_DIR, "users.db")


# ---------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create required tables if they don't exist:
        users  - user accounts + suspension flag
        cases  - case management (title, description, status, created_by, timestamps)
    """
    conn = get_db()

    # Users table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_suspended INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    # Cases table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users (id)
        );
        """
    )

    conn.commit()
    conn.close()


# Run table creation on startup
init_db()


# ---------------------------------------------------------------------
# Utility helpers & decorators
# ---------------------------------------------------------------------
def allowed_file(filename: str, allowed_exts) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_exts


def login_required(view_func):
    """
    Require a logged-in user.
    """
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def admin_required(view_func):
    """
    Only allow access if the logged-in user is 'admin'.
    """
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("username") != "admin":
            flash("Admin access required to view this page.", "warning")
            return redirect(url_for("index"))
        return view_func(*args, **kwargs)
    return wrapped_view


def is_admin() -> bool:
    return session.get("username") == "admin"


# ---------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Public registration for new users.
    The first time you run the app you should create the 'admin' user here.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not username or not password or not confirm:
            flash("Please fill in all fields.", "warning")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "warning")
            return redirect(url_for("register"))

        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing:
            conn.close()
            flash("Username is already taken. Please choose another.", "warning")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        conn.close()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Log a user in using username/password from the SQLite DB.
    Suspended users cannot log in.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if not user:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        if user["is_suspended"]:
            flash("This account is suspended. Please contact the administrator.", "danger")
            return redirect(url_for("login"))

        if check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """
    Log out current user and clear session.
    """
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Admin routes: list, edit, suspend, delete users
# ---------------------------------------------------------------------
@app.route("/admin/users")
@admin_required
def manage_users():
    """
    Admin panel: list all users.
    """
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, is_suspended FROM users ORDER BY username"
    ).fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    """
    Edit another user's username and/or reset password.
    Admin cannot change their own username to avoid locking themselves out.
    """
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, is_suspended FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not user:
        conn.close()
        flash("User not found.", "warning")
        return redirect(url_for("manage_users"))

    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not new_username:
            flash("Username cannot be empty.", "warning")
            return redirect(url_for("edit_user", user_id=user_id))

        # Prevent changing username of admin to something else
        if user["username"] == "admin" and new_username != "admin":
            flash("You cannot change the username of the admin account.", "warning")
            return redirect(url_for("edit_user", user_id=user_id))

        # Check for username conflict with others
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?",
            (new_username, user_id),
        ).fetchone()
        if existing:
            flash("That username is already in use by another account.", "warning")
            return redirect(url_for("edit_user", user_id=user_id))

        # Update username
        conn.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            (new_username, user_id),
        )

        # Optional password reset
        if new_password or confirm:
            if new_password != confirm:
                flash("New password and confirmation do not match.", "warning")
                conn.commit()
                conn.close()
                return redirect(url_for("edit_user", user_id=user_id))

            new_hash = generate_password_hash(new_password)
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id),
            )

        conn.commit()
        conn.close()

        flash("User details updated.", "success")
        return redirect(url_for("manage_users"))

    conn.close()
    return render_template("admin_edit_user.html", user=user)


@app.post("/admin/users/<int:user_id>/toggle-suspend")
@admin_required
def toggle_suspend_user(user_id):
    """
    Toggle suspension status for a user.
    """
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, is_suspended FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not user:
        conn.close()
        flash("User not found.", "warning")
        return redirect(url_for("manage_users"))

    # Optional: prevent suspending yourself (admin)
    if user_id == session.get("user_id"):
        conn.close()
        flash("You cannot suspend your own account while logged in.", "warning")
        return redirect(url_for("manage_users"))

    new_status = 0 if user["is_suspended"] else 1
    conn.execute(
        "UPDATE users SET is_suspended = ? WHERE id = ?",
        (new_status, user_id),
    )
    conn.commit()
    conn.close()

    if new_status:
        flash(f"User '{user['username']}' has been suspended.", "info")
    else:
        flash(f"User '{user['username']}' has been reactivated.", "success")

    return redirect(url_for("manage_users"))


@app.post("/admin/users/<int:user_id>/delete")
@admin_required
def delete_user(user_id):
    """
    Delete a user account. Cannot delete currently logged-in admin.
    """
    current_id = session.get("user_id")
    conn = get_db()
    user = conn.execute(
        "SELECT id, username FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not user:
        conn.close()
        flash("User not found.", "warning")
        return redirect(url_for("manage_users"))

    if user_id == current_id:
        conn.close()
        flash("You cannot delete the account you are logged in with.", "warning")
        return redirect(url_for("manage_users"))

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash(f"User '{user['username']}' has been deleted.", "success")
    return redirect(url_for("manage_users"))


# ---------------------------------------------------------------------
# CASE MANAGEMENT ROUTES
# ---------------------------------------------------------------------
@app.route("/cases")
@login_required
def list_cases():
    """
    List cases.
    - Admin sees all cases.
    - Normal users see only the cases they created.
    """
    conn = get_db()
    if is_admin():
        cases = conn.execute(
            """
            SELECT c.*, u.username AS creator_name
            FROM cases c
            JOIN users u ON c.created_by = u.id
            ORDER BY datetime(c.created_at) DESC
            """
        ).fetchall()
    else:
        cases = conn.execute(
            """
            SELECT c.*, u.username AS creator_name
            FROM cases c
            JOIN users u ON c.created_by = u.id
            WHERE c.created_by = ?
            ORDER BY datetime(c.created_at) DESC
            """,
            (session.get("user_id"),),
        ).fetchall()
    conn.close()
    return render_template("cases_list.html", cases=cases)


@app.route("/cases/new", methods=["GET", "POST"])
@login_required
def create_case():
    """
    Create a new case.
    """
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "Open").strip() or "Open"

        if not title:
            flash("Case title is required.", "warning")
            return redirect(url_for("create_case"))

        now = datetime.utcnow().isoformat(timespec="seconds")
        conn = get_db()
        conn.execute(
            """
            INSERT INTO cases (title, description, status, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, description, status, session.get("user_id"), now, now),
        )
        conn.commit()
        conn.close()

        flash("Case created successfully.", "success")
        return redirect(url_for("list_cases"))

    return render_template("case_form.html", mode="create", case=None)


def user_can_access_case(case_row):
    """
    Returns True if current user is allowed to access this case.
    Admin -> always True
    Normal user -> only if they created it
    """
    if is_admin():
        return True
    return case_row["created_by"] == session.get("user_id")


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    """
    View details of a case.
    """
    conn = get_db()
    case = conn.execute(
        """
        SELECT c.*, u.username AS creator_name
        FROM cases c
        JOIN users u ON c.created_by = u.id
        WHERE c.id = ?
        """,
        (case_id,),
    ).fetchone()
    conn.close()

    if not case:
        flash("Case not found.", "warning")
        return redirect(url_for("list_cases"))

    if not user_can_access_case(case):
        flash("You are not allowed to view this case.", "danger")
        return redirect(url_for("list_cases"))

    return render_template("case_detail.html", case=case)


@app.route("/cases/<int:case_id>/edit", methods=["GET", "POST"])
@login_required
def edit_case(case_id):
    """
    Edit an existing case.
    Admin can edit any case.
    Normal users can only edit their own cases.
    """
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()

    if not case:
        conn.close()
        flash("Case not found.", "warning")
        return redirect(url_for("list_cases"))

    if not user_can_access_case(case):
        conn.close()
        flash("You are not allowed to edit this case.", "danger")
        return redirect(url_for("list_cases"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "").strip()

        if not title:
            flash("Case title is required.", "warning")
            return redirect(url_for("edit_case", case_id=case_id))

        now = datetime.utcnow().isoformat(timespec="seconds")
        conn.execute(
            """
            UPDATE cases
            SET title = ?, description = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (title, description, status or "Open", now, case_id),
        )
        conn.commit()
        conn.close()

        flash("Case updated successfully.", "success")
        return redirect(url_for("case_detail", case_id=case_id))

    conn.close()
    return render_template("case_form.html", mode="edit", case=case)


@app.post("/cases/<int:case_id>/delete")
@login_required
def delete_case(case_id):
    """
    Delete a case.
    Admin can delete any case.
    Normal user can only delete their own case.
    """
    conn = get_db()
    case = conn.execute(
        "SELECT * FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()

    if not case:
        conn.close()
        flash("Case not found.", "warning")
        return redirect(url_for("list_cases"))

    if not user_can_access_case(case):
        conn.close()
        flash("You are not allowed to delete this case.", "danger")
        return redirect(url_for("list_cases"))

    conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    conn.commit()
    conn.close()

    flash("Case deleted.", "info")
    return redirect(url_for("list_cases"))


# ---------------------------------------------------------------------
# Core UI routes (protected)
# ---------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    """
    Main dashboard.
    """
    return render_template("index.html")


@app.route("/search-image", methods=["POST"])
@login_required
def search_image():
    """
    Handles sketch/photo upload.
    For now: returns DUMMY results.
    """
    file = request.files.get("query_image")

    if not file or file.filename == "":
        flash("Please choose a sketch or photo to upload.", "warning")
        return redirect(url_for("index"))

    if not allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
        flash("Unsupported image type. Please upload a JPG or PNG.", "warning")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    save_path = os.path.join(IMAGE_UPLOAD_DIR, filename)
    file.save(save_path)

    dummy_results = [
        {"label": "Person_A", "score": 0.23, "source": "suspect_ali_1.jpg"},
        {"label": "Person_B", "score": 0.41, "source": "suspect_maria_2.png"},
        {"label": "Unknown", "score": 0.68, "source": "unknown_3.png"},
    ]

    query_image_url = url_for("static", filename=f"uploads/images/{filename}")

    return render_template(
        "image_results.html",
        query_image=query_image_url,
        results=dummy_results,
    )


@app.route("/search-video", methods=["POST"])
@login_required
def search_video():
    """
    Handles CCTV/video upload.
    For now: returns DUMMY match timeline.
    """
    file = request.files.get("video_file")

    if not file or file.filename == "":
        flash("Please choose a CCTV/video file to upload.", "warning")
        return redirect(url_for("index"))

    if not allowed_file(file.filename, ALLOWED_VIDEO_EXTENSIONS):
        flash("Unsupported video type. Please upload MP4 / AVI / MOV / MKV.", "warning")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    save_path = os.path.join(VIDEO_UPLOAD_DIR, filename)
    file.save(save_path)

    dummy_matches = [
        {"time": "00:05", "label": "Person_A", "score": 0.27},
        {"time": "00:23", "label": "Person_B", "score": 0.35},
        {"time": "01:02", "label": "Unknown", "score": 0.62},
    ]

    return render_template(
        "video_results.html",
        video_name=filename,
        matches=dummy_matches,
    )


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
