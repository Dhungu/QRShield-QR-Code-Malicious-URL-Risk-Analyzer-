from flask_sqlalchemy import SQLAlchemy

# A single shared SQLAlchemy instance. Models import this instead of
# creating their own, and app.py calls db.init_app(app) once configured.
db = SQLAlchemy()
