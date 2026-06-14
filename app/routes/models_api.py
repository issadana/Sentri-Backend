from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.utils.decorators import admin_required
from app import db
from app.models import ModelVersion


models_bp = Blueprint("models", __name__, url_prefix="/models")

# Get all model versions of the logged-in user (newest first)
@models_bp.route("", methods=["GET"])
@jwt_required()
@admin_required
def get_models():
    """
Get model versions.
---
tags:
  - Model Versions
security:
  - Bearer: []
responses:
  200:
    description: List of model versions
"""
    current_user_id = get_jwt_identity()

    models = ModelVersion.query.filter_by(
        user_id=current_user_id
    ).order_by(
        ModelVersion.deployed_at.desc()
    ).all()

    result = []

    for model in models:
        result.append({
            "id": model.id,
            "name": model.name,
            "filename": model.filename,
            "accuracy": model.accuracy,
            "samples": model.samples,
            "is_active": model.is_active,
            "deployed_at": model.deployed_at.isoformat()
        })

    return jsonify(result), 200


# Create and save a new AI model version for the logged-in user
@models_bp.route("", methods=["POST"])
@jwt_required()
@admin_required
def create_model_version():
    """
Create model version.
---
tags:
  - Model Versions
security:
  - Bearer: []
consumes:
  - application/json
responses:
  201:
    description: Model version created
"""
    current_user_id = get_jwt_identity()
    data = request.get_json()

    name = data.get("name")
    filename = data.get("filename")
    accuracy = data.get("accuracy")
    samples = data.get("samples")
    is_active = data.get("is_active", False)

    if not name or not filename:
        return jsonify({"error": "Model name and filename are required"}), 400

    new_model = ModelVersion(
        user_id=current_user_id,
        name=name,
        filename=filename,
        accuracy=accuracy,
        samples=samples,
        is_active=is_active
    )

    db.session.add(new_model)
    db.session.commit()

    return jsonify({
        "message": "Model version created",
        "model": {
            "id": new_model.id,
            "name": new_model.name,
            "filename": new_model.filename,
            "accuracy": new_model.accuracy,
            "samples": new_model.samples,
            "is_active": new_model.is_active,
            "deployed_at": new_model.deployed_at.isoformat()
        }
    }), 201


# Activate a selected model and deactivate all other user models
@models_bp.route("/<int:model_id>/activate", methods=["POST"])
@jwt_required()
@admin_required
def activate_model(model_id):
    """
Activate model version.
---
tags:
  - Model Versions
security:
  - Bearer: []
parameters:
  - in: path
    name: model_id
    required: true
    type: integer
responses:
  200:
    description: Model activated successfully
"""
    current_user_id = get_jwt_identity()

    model = ModelVersion.query.filter_by(
        id=model_id,
        user_id=current_user_id
    ).first()

    if not model:
        return jsonify({"error": "Model not found"}), 404

    ModelVersion.query.filter_by(
        user_id=current_user_id
    ).update({"is_active": False})

    model.is_active = True

    db.session.commit()

    return jsonify({
        "message": "Model activated successfully",
        "active_model": {
            "id": model.id,
            "name": model.name,
            "filename": model.filename
        }
    }), 200

