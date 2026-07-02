from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
import bcrypt
import re

from app import db
from app.models import User, UserSettings, RefreshToken

# Create a Blueprint to group all authentication routes under /auth
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@auth_bp.route("/register", methods=["POST"]) #this route expects incoming data.
def register():
    """
    Register a new user.
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              example: hanine
            email:
              type: string
              example: hanine@test.com
            password:
              type: string
              example: password123
    responses:
      201:
        description: User registered successfully
      400:
        description: Invalid input
      409:
        description: Email or username already exists
    """
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Email, username, and password are required"}), 400
    
    if len(email) > 255:
        return jsonify({"error": "Email too long"}), 400
    
    if len(username) > 100:
        return jsonify({"error": "Username too long"}), 400
    
    if not EMAIL_REGEX.match(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered"}), 409
    
    existing_username = User.query.filter_by(username=username).first()
    if existing_username:
        return jsonify({"error": "Username already taken"}), 409

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    new_user = User(
        username=username,
        email=email,
        password=hashed_password.decode("utf-8")
    )

    db.session.add(new_user)
    db.session.flush()#temporarily insert row so database generates the id

    default_settings = UserSettings(user_id=new_user.id)
    db.session.add(default_settings)

    db.session.commit()#save everything

    access_token = create_access_token(identity=str(new_user.id))
    refresh_token = create_refresh_token(identity=str(new_user.id))

    from flask_jwt_extended import decode_token
    decoded_refresh = decode_token(refresh_token)
    jti = decoded_refresh["jti"]

    saved_refresh_token = RefreshToken(
    jti=jti,
    user_id=new_user.id
    )

    db.session.add(saved_refresh_token)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email
        }
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    User Login
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              example: hanine@test.com
            password:
              type: string
              example: password123
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    password_correct = bcrypt.checkpw(
        password.encode("utf-8"),
        user.password.encode("utf-8")
    )

    if not password_correct:
        return jsonify({"error": "Invalid credentials"}), 401
     

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    from flask_jwt_extended import decode_token
    decoded_refresh = decode_token(refresh_token)
    jti = decoded_refresh["jti"]

    saved_refresh_token = RefreshToken(
    jti=jti,
    user_id=user.id
    )

    db.session.add(saved_refresh_token)
    db.session.commit()
 #This return sends login success data back to the app, including tokens and user information.
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    """
    Get current logged-in user.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Current user returned
      401:
        description: Unauthorized
      404:
        description: User not found
    """
    current_user_id = get_jwt_identity()

    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin
    }), 200



@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)#This route accepts only a refresh token, not an access token.
def refresh():
    """
    Refresh access token.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: New access token generated
      401:
        description: Refresh token invalid or revoked
    """
    current_user_id = get_jwt_identity()

    jti = get_jwt()["jti"]

    stored_token = RefreshToken.query.filter_by(jti=jti).first()

    if not stored_token or stored_token.revoked:
        return jsonify({"error": "Refresh token revoked"}), 401

    new_access_token = create_access_token(identity=current_user_id)

    return jsonify({
        "access_token": new_access_token
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required(refresh=True)
def logout():
    """
    Logout user and revoke refresh token.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      204:
        description: Logged out successfully
      401:
        description: Unauthorized
    """
    jti = get_jwt()["jti"]

    stored_token = RefreshToken.query.filter_by(jti=jti).first()

    if stored_token:
        stored_token.revoked = True
        db.session.commit()

    return "", 204