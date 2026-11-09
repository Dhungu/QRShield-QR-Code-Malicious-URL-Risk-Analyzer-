"""Database models for QRShield.

Schema overview
---------------
users        one row per registered account.
scan_logs    one row per QR scan / URL analysis. user_id is nullable so
             anonymous scans (no login) are still stored independently.
scan_checks  one row per heuristic result for a scan (normalized out of
             scan_logs instead of storing an 11-item list/JSON blob inline,
             so a specific failed rule can be queried directly later).
feedback     one row per "report this as a false positive" submission,
             linked to the scan it's about.

Relationships
-------------
User (1) ----- (many) ScanLog        -- a user can have many scans
ScanLog (1) --- (many) ScanCheck     -- a scan has many heuristic checks
ScanLog (1) --- (many) Feedback      -- a scan can receive multiple reports
"""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scans = db.relationship("ScanLog", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    # Nullable / optional foreign key: scans work whether or not the
    # person is logged in.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)

    extracted_url = db.Column(db.Text, nullable=False)
    hostname = db.Column(db.String(255))
    protocol = db.Column(db.String(10))
    url_length = db.Column(db.Integer)

    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)  # "LOW RISK" / "MEDIUM RISK" / "HIGH RISK"
    recommendation = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    checks = db.relationship(
        "ScanCheck", backref="scan", lazy=True, cascade="all, delete-orphan"
    )
    feedback_entries = db.relationship(
        "Feedback", backref="scan", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<ScanLog {self.id} {self.hostname} score={self.risk_score}>"


class ScanCheck(db.Model):
    """One heuristic result for one scan (normalized out of ScanLog)."""

    __tablename__ = "scan_checks"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_logs.id"), nullable=False, index=True)
    text = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # "pass" or "warn"


class Feedback(db.Model):
    """A "this looks like a false positive" report tied to one scan."""

    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_logs.id"), nullable=False, index=True)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
