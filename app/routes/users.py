from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import bcrypt

from app import db
from app.models import User


users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/me", methods=["PUT"])
@jwt_required()
def update_me():
    """
    Update current user profile.
    ---
    tags:
      - Users
    security:
      - Bearer: []
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              example: hanine_new
            current_password:
              type: string
              example: password123
            new_password:
              type: string
              example: newpassword123
    responses:
      200:
        description: User updated successfully
      400:
        description: Invalid request
      401:
        description: Current password incorrect
      404:
        description: User not found
      409:
        description: Username already taken
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()

    username = data.get("username")
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if new_password and not current_password:
        return jsonify({"error": "Current password is required to change password"}), 400

    if username:
        existing_username = User.query.filter_by(username=username).first()

        if existing_username and existing_username.id != user.id:
            return jsonify({"error": "Username already taken"}), 409

        user.username = username

    if new_password:
        password_correct = bcrypt.checkpw(
            current_password.encode("utf-8"),
            user.password.encode("utf-8")
        )

        if not password_correct:
            return jsonify({"error": "Current password is incorrect"}), 401

        if len(new_password) < 8:
            return jsonify({"error": "New password must be at least 8 characters"}), 400

        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        )

        user.password = hashed_password.decode("utf-8")

    db.session.commit()

    return jsonify({
        "message": "User updated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }), 200