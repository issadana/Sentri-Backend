from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.models import AclEntry
import ipaddress

acl_bp = Blueprint("acl", __name__, url_prefix="/acl")

# Get all ACL (allowed IP) entries of the logged-in user
@acl_bp.route("", methods=["GET"])
@jwt_required()
def get_acl():
    """
    Get ACL entries.
    ---
    tags:
      - ACL
    security:
      - Bearer: []
    responses:
      200:
        description: List of allowed IPs
      401:
        description: Unauthorized
    """
    current_user_id = get_jwt_identity()

    entries = AclEntry.query.filter_by(user_id=current_user_id).order_by(
        AclEntry.added_at.desc()
    ).all()

    result = []

    for entry in entries:
        result.append({
            "id": entry.id,
            "ip": entry.ip,
            "notes": entry.notes,
            "added_at": entry.added_at.isoformat()
        })

    return jsonify(result), 200

# Add a new IP address to the logged-in user's ACL list
@acl_bp.route("", methods=["POST"])
@jwt_required()
def add_acl_entry():
    """
    Add IP to ACL.
    ---
    tags:
      - ACL
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
          required:
            - ip
          properties:
            ip:
              type: string
              example: 10.0.0.1
            notes:
              type: string
              example: Trusted WireGuard server
    responses:
      201:
        description: IP added to ACL
      400:
        description: Invalid input
      409:
        description: IP already exists
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()

    ip = data.get("ip")
    notes = data.get("notes")

    if notes and len(notes) > 255:
       return jsonify({"error": "notes too long"}), 400

    if not ip:
        return jsonify({"error": "IP is required"}), 400
    
    try:
       ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    existing_entry = AclEntry.query.filter_by(
        user_id=current_user_id,
        ip=ip
    ).first()

    if existing_entry:
        return jsonify({"error": "IP already in ACL"}), 409

    new_entry = AclEntry(
        user_id=current_user_id,
        ip=ip,
        notes=notes
    )

    db.session.add(new_entry)
    db.session.commit()

    return jsonify({
        "message": "IP added to ACL",
        "entry": {
            "id": new_entry.id,
            "ip": new_entry.ip,
            "notes": new_entry.notes,
            "added_at": new_entry.added_at.isoformat()
        }
    }), 201

# Delete a specific Id from the logged-in user's ACL list
@acl_bp.route("/<int:entry_id>", methods=["DELETE"])
@jwt_required()
def delete_acl_entry(entry_id):
    """
    Delete ACL entry by ID.
    ---
    tags:
      - ACL
    security:
      - Bearer: []
    parameters:
      - in: path
        name: entry_id
        required: true
        type: integer
        example: 1
    responses:
      204:
        description: ACL entry deleted
      404:
        description: ACL entry not found
    """
    current_user_id = get_jwt_identity()

    entry = AclEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()

    if not entry:
        return jsonify({"error": "ACL entry not found"}), 404

    db.session.delete(entry)
    db.session.commit()

    return "", 204

# Remove all ACL entries of the logged-in user
@acl_bp.route("", methods=["DELETE"])
@jwt_required()
def clear_acl():
    current_user_id = get_jwt_identity()

    AclEntry.query.filter_by(user_id=current_user_id).delete()
    db.session.commit()

    return "", 204

