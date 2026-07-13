"""Fix admin password hash when stored as plain text."""

import os
import sys

import bcrypt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app, db
from app.models import User


def fix_admin_password(email: str, password: str):
    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"No user found for {email}")
            return

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        user.password = hashed.decode("utf-8")
        if not user.is_admin:
            user.is_admin = True
        db.session.commit()
        print(f"Updated password hash for {email} ({user.username}), is_admin={user.is_admin}")


if __name__ == "__main__":
    fix_admin_password("admin@gmail.com", "Admin123!")
