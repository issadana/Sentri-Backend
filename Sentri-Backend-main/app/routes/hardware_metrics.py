from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

from app import db
from app.models import HardwareMetric


hardware_metrics_bp = Blueprint(
    "hardware_metrics",
    __name__,
    url_prefix="/hardware-metrics"
)

@hardware_metrics_bp.route("", methods=["POST"])
@jwt_required()
def create_metric():
    """
    Create hardware metrics snapshot.
    ---
    tags:
      - Hardware Metrics
    security:
      - Bearer: []
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - cpu_usage
            - ram_used_mb
            - ram_total_mb
          properties:
            cpu_usage:
              type: number
              example: 42.5
            ram_used_mb:
              type: integer
              example: 4096
            ram_total_mb:
              type: integer
              example: 8192
            battery_level:
              type: number
              example: 76
    responses:
      201:
        description: Hardware metrics saved
      400:
        description: Invalid data
    """

    current_user_id = get_jwt_identity()

    data = request.get_json()

    cpu_usage = data.get("cpu_usage")
    ram_used_mb = data.get("ram_used_mb")
    ram_total_mb = data.get("ram_total_mb")
    battery_level = data.get("battery_level")

    if cpu_usage is None:
        return jsonify({"error": "cpu_usage is required"}), 400

    if ram_used_mb is None:
        return jsonify({"error": "ram_used_mb is required"}), 400

    if ram_total_mb is None:
        return jsonify({"error": "ram_total_mb is required"}), 400

    metric = HardwareMetric(
        user_id=current_user_id,
        cpu_usage=cpu_usage,
        ram_used_mb=ram_used_mb,
        ram_total_mb=ram_total_mb,
        battery_level=battery_level
    )

    db.session.add(metric)
    db.session.commit()

    return jsonify({
        "message": "Hardware metric saved",
        "id": metric.id
    }), 201


@hardware_metrics_bp.route("", methods=["GET"])
@jwt_required()
def get_metrics():
    """
Get hardware metrics history.
---
tags:
  - Hardware Metrics
security:
  - Bearer: []
parameters:
  - in: query
    name: from_date
    type: string
  - in: query
    name: to_date
    type: string
responses:
  200:
    description: Hardware metrics history
"""
    current_user_id = get_jwt_identity()

    query = HardwareMetric.query.filter_by(
        user_id=current_user_id
    )

    from_date = request.args.get("from_date")
    to_date = request.args.get("to_date")

    if from_date:
        query = query.filter(
            HardwareMetric.recorded_at >= datetime.fromisoformat(from_date)
        )

    if to_date:
        query = query.filter(
            HardwareMetric.recorded_at <= datetime.fromisoformat(to_date)
        )

    metrics = query.order_by(
        HardwareMetric.recorded_at.desc()
    ).all()

    result = []

    for metric in metrics:
        result.append({
            "id": metric.id,
            "cpu_usage": metric.cpu_usage,
            "ram_used_mb": metric.ram_used_mb,
            "ram_total_mb": metric.ram_total_mb,
            "battery_level": metric.battery_level,
            "recorded_at": metric.recorded_at
        })

    return jsonify(result), 200
