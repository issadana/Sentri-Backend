"""List admin users in the deployed database."""

from app import create_app
from app.models import User


def main():
    app = create_app()
    with app.app_context():
        admins = User.query.filter_by(is_admin=True).all()
        if not admins:
            print("No admin users found.")
            return
        for user in admins:
            print(f"- id={user.id} username={user.username} email={user.email}")


if __name__ == "__main__":
    main()
