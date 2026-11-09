import os
import re
import uuid

import cv2
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

from analysis import analyze_url
from extensions import db
from models import Feedback, ScanCheck, ScanLog, User

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


app = Flask(__name__)

# In production, set SECRET_KEY via an environment variable rather than
# relying on this fallback.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "qrshield.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}

db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to view that page."
login_manager.login_message_category = "error"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


def save_scan(result, user_id=None):
    """Persist an analyze_url() result as a ScanLog row plus its ScanCheck rows."""
    scan = ScanLog(
        user_id=user_id,
        extracted_url=result["url"],
        hostname=result["hostname"],
        protocol=result["protocol"],
        url_length=result["length"],
        risk_score=result["score"],
        risk_level=result["level"],
        recommendation=result["recommendation"],
    )
    for check in result["checks"]:
        scan.checks.append(ScanCheck(text=check["text"], status=check["status"]))

    db.session.add(scan)
    db.session.commit()
    return scan.id

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Your session expired or the form was tampered with — please try again.", "error")
    return redirect(url_for("index"))

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(_exc):
    return render_template(
        "index.html",
        result=None,
        error="That image is larger than the 5 MB limit. Please upload a smaller file.",
    ), 413


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        if "qr_image" not in request.files:
            return render_template("index.html", result=None, error="No image uploaded.")

        file = request.files["qr_image"]

        if file.filename == "":
            return render_template(
                "index.html", result=None, error="Please select a QR code image."
            )

        filename = secure_filename(file.filename)
        extension = os.path.splitext(filename)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            return render_template(
                "index.html",
                result=None,
                error="Please upload a PNG, JPG, JPEG, or WEBP image.",
            )

        unique_name = f"{uuid.uuid4().hex}{extension}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

        try:
            file.save(filepath)
            image = cv2.imread(filepath)

            if image is None:
                error = "The uploaded image could not be read. Please try a different file."
            else:
                qr_detector = cv2.QRCodeDetector()
                data, points, _ = qr_detector.detectAndDecode(image)
                
                if data:
                    data = data.strip()

                    if re.match(r"^https?://", data, re.IGNORECASE):
                        result = analyze_url(data)
                        user_id = current_user.id if current_user.is_authenticated else None
                        result["id"] = save_scan(result, user_id=user_id)
                    else:
                        error = "QR code detected, but it does not contain a web URL."
                else:
                    error = "Could not detect a QR code in this image."
        except Exception as exc:
            app.logger.exception("Scan error: %s", exc)
            error = "Something went wrong while analyzing the image."
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    return render_template("index.html", result=result, error=error)


@app.route("/scan/<int:scan_id>/feedback", methods=["POST"])
def submit_feedback(scan_id):
    scan = ScanLog.query.get_or_404(scan_id)
    comment = request.form.get("comment", "").strip()

    db.session.add(Feedback(scan_id=scan.id, comment=comment or None))
    db.session.commit()

    flash("Thanks — we've logged this as a possible false positive.", "success")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Please fill in every field.", "error")
        elif password != confirm_password:
            flash("Passwords don't match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Welcome to QRShield!", "success")
            return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))

        flash("Incorrect username/email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/history")
@login_required
def history():
    scans = (
        ScanLog.query.filter_by(user_id=current_user.id)
        .order_by(ScanLog.timestamp.desc())
        .all()
    )
    return render_template("history.html", scans=scans)


if __name__ == "__main__":
    # Debug mode must opt in explicitly - Flask's debugger exposes an
    # interactive shell and should never run with debug=True by default.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
