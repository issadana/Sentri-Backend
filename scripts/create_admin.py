"""Create or promote an admin user for the NOVA dashboard."""

import argparse
import getpass
import sys

import bcrypt

from app import create_app, db
from app.models import User, UserSettings


def ensure_admin(email, username, password):
    app = create_app()
    with app.app_context():
        existing = User.query.filter_by(email=email).first()
        if existing:
            if not existing.is_admin:
                existing.is_admin = True
                db.session.commit()
                print(f"Promoted existing user '{existing.username}' to admin.")
            else:
                print(f"Admin user already exists: {existing.email} ({existing.username})")
            return

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        user = User(
            username=username,
            email=email,
            password=hashed.decode("utf-8"),
            is_admin=True,
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(UserSettings(user_id=user.id))
        db.session.commit()
        print(f"Created admin user: {email} ({username})")


def main():
    parser = argparse.ArgumentParser(description="Create or promote a dashboard admin user.")
    parser.add_argument("--email", help="Admin email used for JWT login")
    parser.add_argument("--username", help="Display username")
    parser.add_argument("--password", help="Account password (min 8 chars)")
    args = parser.parse_args()

    email = args.email or input("Admin email: ").strip()
    username = args.username or input("Username: ").strip()
    password = args.password or getpass.getpass("Password: ")

    if not email or not username or len(password) < 8:
        print("Email, username, and password (8+ chars) are required.", file=sys.stderr)
        sys.exit(1)

    ensure_admin(email, username, password)


if __name__ == "__main__":
    main()
