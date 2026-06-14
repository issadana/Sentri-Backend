from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.models import BlacklistEntry
import ipaddress

blacklist_bp = Blueprint("blacklist", __name__, url_prefix="/blacklist")

# Get all blacklisted IP addresses of the logged-in user
@blacklist_bp.route("", methods=["GET"])
@jwt_required()
def get_blacklist():
    """
    Get blacklist entries.
    ---
    tags:
      - Blacklist
    security:
      - Bearer: []
    responses:
      200:
        description: List of blacklisted IPs
      401:
        description: Unauthorized
    """
    current_user_id = get_jwt_identity()

    entries = BlacklistEntry.query.filter_by(user_id=current_user_id).order_by(
        BlacklistEntry.added_at.desc()
    ).all()

    result = []

    for entry in entries:
        result.append({
            "id": entry.id,
            "ip": entry.ip,
            "reason": entry.reason,
            "bf_score": entry.bf_score,
            "dos_score": entry.dos_score,
            "notes": entry.notes,
            "added_at": entry.added_at.isoformat()
        })

    return jsonify(result), 200

# Add a new IP address to the logged-in user's blacklist
@blacklist_bp.route("", methods=["POST"])
@jwt_required()
def add_blacklist_entry():
    """
    Add IP to blacklist.
    ---
    tags:
      - Blacklist
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
              example: 192.168.1.10
            reason:
              type: string
              example: manual
            notes:
              type: string
              example: Suspicious traffic
    responses:
      201:
        description: IP added to blacklist
      400:
        description: Invalid input
      409:
        description: IP already blacklisted
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()

    ip = data.get("ip")
    reason = data.get("reason", "manual")
    bf_score = data.get("bf_score")
    dos_score = data.get("dos_score")
    notes = data.get("notes")

    if notes and len(notes) > 255:
       return jsonify({"error": "notes too long"}), 400

    if reason and len(reason) > 20:
       return jsonify({"error": "reason too long"}), 400

    if not ip:
        return jsonify({"error": "IP is required"}), 400
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    existing_entry = BlacklistEntry.query.filter_by(
        user_id=current_user_id,
        ip=ip
    ).first()

    if existing_entry:
        return jsonify({"error": "IP already blacklisted"}), 409

    new_entry = BlacklistEntry(
        user_id=current_user_id,
        ip=ip,
        reason=reason,
        bf_score=bf_score,
        dos_score=dos_score,
        notes=notes
    )

    db.session.add(new_entry)
    db.session.commit()

    return jsonify({
        "message": "IP added to blacklist",
        "entry": {
            "id": new_entry.id,
            "ip": new_entry.ip,
            "reason": new_entry.reason,
            "bf_score": new_entry.bf_score,
            "dos_score": new_entry.dos_score,
            "notes": new_entry.notes,
            "added_at": new_entry.added_at.isoformat()
        }
    }), 201

# Delete a specific Id from the logged-in user's blacklist
@blacklist_bp.route("/<int:entry_id>", methods=["DELETE"])
@jwt_required()
def delete_blacklist_entry(entry_id):
    """
    Delete blacklist entry by ID.
    ---
    tags:
      - Blacklist
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
        description: Blacklist entry deleted
      404:
        description: Blacklist entry not found
    """
    current_user_id = get_jwt_identity()

    entry = BlacklistEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()

    if not entry:
        return jsonify({"error": "Blacklist entry not found"}), 404

    db.session.delete(entry)
    db.session.commit()

    return "", 204

# Remove all blacklisted IP addresses of the logged-in user
@blacklist_bp.route("", methods=["DELETE"])
@jwt_required()
def clear_blacklist():
    current_user_id = get_jwt_identity()

    BlacklistEntry.query.filter_by(user_id=current_user_id).delete()
    db.session.commit()

    return "", 204