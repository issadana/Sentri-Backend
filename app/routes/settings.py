from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.models import UserSettings


settings_bp = Blueprint("settings", __name__, url_prefix="/settings")
# Get the current settings of the logged-in user
@settings_bp.route("", methods=["GET"])
@jwt_required()
def get_settings():
    """
    Get user settings.
    ---
    tags:
      - Settings
    security:
      - Bearer: []
    responses:
      200:
        description: Current user settings
      404:
        description: Settings not found
    """
    current_user_id = get_jwt_identity()

    settings = UserSettings.query.filter_by(
        user_id=current_user_id
    ).first()

    if not settings:
        return jsonify({"error": "Settings not found"}), 404

    return jsonify({
        "block_threshold": settings.block_threshold,
        "warn_threshold": settings.warn_threshold,
        "flood_detection": settings.flood_detection,
        "syn_flood_detection": settings.syn_flood_detection,
        "flood_pkt_per_sec": settings.flood_pkt_per_sec,
        "syn_flood_per_sec": settings.syn_flood_per_sec,
        "bf_model_enabled": settings.bf_model_enabled,
        "dos_model_enabled": settings.dos_model_enabled,
        "max_log_entries": settings.max_log_entries,
        "log_system_traffic": settings.log_system_traffic
    }), 200


# Update the current settings of the logged-in user
@settings_bp.route("", methods=["PUT"])
@jwt_required()
def update_settings():
    """
    Update user settings.
    ---
    tags:
      - Settings
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
            block_threshold:
              type: number
              example: 0.8
            warn_threshold:
              type: number
              example: 0.5
            flood_detection:
              type: boolean
              example: true
            syn_flood_detection:
              type: boolean
              example: true
            flood_pkt_per_sec:
              type: integer
              example: 1000
            syn_flood_per_sec:
              type: integer
              example: 100
            bf_model_enabled:
              type: boolean
              example: true
            dos_model_enabled:
              type: boolean
              example: true
            max_log_entries:
              type: integer
              example: 200
            log_system_traffic:
              type: boolean
              example: false
    responses:
      200:
        description: Settings updated successfully
      400:
        description: Invalid settings values
    """
    current_user_id = get_jwt_identity()

    settings = UserSettings.query.filter_by(
        user_id=current_user_id
    ).first()

    if not settings:
        return jsonify({"error": "Settings not found"}), 404

    data = request.get_json()

    if "block_threshold" in data:
        if not 0 <= data["block_threshold"] <= 1:
           return jsonify({
            "error": "block_threshold must be between 0 and 1"
        }), 400

    if "warn_threshold" in data:
        if not 0 <= data["warn_threshold"] <= 1:
           return jsonify({
            "error": "warn_threshold must be between 0 and 1"
        }), 400

    if "flood_pkt_per_sec" in data:
        if data["flood_pkt_per_sec"] <= 0:
           return jsonify({
            "error": "flood_pkt_per_sec must be greater than 0"
        }), 400

    if "syn_flood_per_sec" in data:
        if data["syn_flood_per_sec"] <= 0:
           return jsonify({
            "error": "syn_flood_per_sec must be greater than 0"
        }), 400

    if "max_log_entries" in data:
        if data["max_log_entries"] <= 0:
           return jsonify({
            "error": "max_log_entries must be greater than 0"
        }), 400
    

    settings.block_threshold = data.get(
        "block_threshold",
        settings.block_threshold
    )

    settings.warn_threshold = data.get(
        "warn_threshold",
        settings.warn_threshold
    )

    settings.flood_detection = data.get(
        "flood_detection",
        settings.flood_detection
    )

    settings.syn_flood_detection = data.get(
        "syn_flood_detection",
        settings.syn_flood_detection
    )

    settings.flood_pkt_per_sec = data.get(
        "flood_pkt_per_sec",
        settings.flood_pkt_per_sec
    )

    settings.syn_flood_per_sec = data.get(
        "syn_flood_per_sec",
        settings.syn_flood_per_sec
    )

    settings.bf_model_enabled = data.get(
        "bf_model_enabled",
        settings.bf_model_enabled
    )

    settings.dos_model_enabled = data.get(
        "dos_model_enabled",
        settings.dos_model_enabled
    )

    settings.max_log_entries = data.get(
        "max_log_entries",
        settings.max_log_entries
    )
    
    settings.log_system_traffic = data.get(
    "log_system_traffic",
    settings.log_system_traffic
    )

    db.session.commit()

    return jsonify({
        "message": "Settings updated successfully"
    }), 200