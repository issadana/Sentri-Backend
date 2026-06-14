from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.utils.decorators import admin_required
from app import db
from app.models import UnknownEvent, TrainingSample


events_bp = Blueprint("events", __name__, url_prefix="/events")


@events_bp.route("/unknown", methods=["POST"])
@jwt_required()
def create_unknown_event():
    """
Create unknown event.
---
tags:
  - Unknown Events
security:
  - Bearer: []
consumes:
  - application/json
responses:
  201:
    description: Unknown event created
"""
    current_user_id = get_jwt_identity()
    data = request.get_json()

    src_port = data.get("src_port")
    dst_port = data.get("dst_port")
    protocol = data.get("protocol")

    if src_port is not None and not (0 <= src_port <= 65535):
       return jsonify({"error": "src_port must be between 0 and 65535"}), 400

    if dst_port is not None and not (0 <= dst_port <= 65535):
       return jsonify({"error": "dst_port must be between 0 and 65535"}), 400

    if protocol is not None and protocol not in [1, 6, 17]:
       return jsonify({"error": "protocol must be 1, 6, or 17"}), 400

    new_event = UnknownEvent(
        user_id=current_user_id,
        src_ip=data.get("src_ip"),
        src_port=data.get("src_port"),
        dst_port=data.get("dst_port"),
        protocol=data.get("protocol"),
        size_bytes=data.get("size_bytes"),
        flow_iat_mean=data.get("flow_iat_mean"),
        tot_fwd_pkts=data.get("tot_fwd_pkts"),
        pkt_size_avg=data.get("pkt_size_avg"),
        flow_duration=data.get("flow_duration"),
        bf_score=data.get("bf_score"),
        dos_score=data.get("dos_score"),
        status="pending"
    )

    db.session.add(new_event)
    db.session.commit()

    return jsonify({
        "message": "Unknown event created",
        "event": {
            "id": new_event.id,
            "status": new_event.status,
            "created_at": new_event.created_at.isoformat()
        }
    }), 201


@events_bp.route("/unknown", methods=["GET"])
@jwt_required()
def get_unknown_events():
    """
Get unknown events.
---
tags:
  - Unknown Events
security:
  - Bearer: []
parameters:
  - in: query
    name: status
    type: string
responses:
  200:
    description: List of unknown events
"""
    current_user_id = get_jwt_identity()

    query = UnknownEvent.query.filter_by(
        user_id=current_user_id
    )

    status = request.args.get("status")

    if status:
        query = query.filter_by(status=status)

    events = query.order_by(
        UnknownEvent.created_at.desc()
    ).all()

    result = []

    for event in events:
        result.append({
            "id": event.id,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "size_bytes": event.size_bytes,
            "bf_score": event.bf_score,
            "dos_score": event.dos_score,
            "status": event.status,
            "label": event.label,
            "created_at": event.created_at.isoformat()
        })

    return jsonify(result), 200


@events_bp.route("/unknown/<int:event_id>/label", methods=["POST"])
@jwt_required()
@admin_required
def label_unknown_event(event_id):
    """
Label unknown event.
---
tags:
  - Unknown Events
security:
  - Bearer: []
parameters:
  - in: path
    name: event_id
    required: true
    type: integer
responses:
  200:
    description: Event labeled successfully
"""
    current_user_id = get_jwt_identity()
    data = request.get_json()

    label = data.get("label")
    
    if label and len(label) > 20:
       return jsonify({"error": "label too long"}), 400

    if not label:
        return jsonify({"error": "Label is required"}), 400

    event = UnknownEvent.query.filter_by(
        id=event_id,
        user_id=current_user_id
    ).first()

    if not event:
        return jsonify({"error": "Event not found"}), 404

    event.status = "labeled"
    event.label = label

    training_sample = TrainingSample(
        event_id=event.id,
        label=label,
        protocol=event.protocol,
        flow_iat_mean=event.flow_iat_mean,
        tot_fwd_pkts=event.tot_fwd_pkts,
        pkt_size_avg=event.pkt_size_avg,
        flow_duration=event.flow_duration
    )

    db.session.add(training_sample)
    db.session.commit()

    return jsonify({
        "message": "Event labeled successfully"
    }), 200


@events_bp.route("/unknown/<int:event_id>/dismiss", methods=["POST"])
@jwt_required()
@admin_required
def dismiss_unknown_event(event_id):
    """
Dismiss unknown event.
---
tags:
  - Unknown Events
security:
  - Bearer: []
parameters:
  - in: path
    name: event_id
    required: true
    type: integer
responses:
  200:
    description: Event dismissed successfully
"""
    current_user_id = get_jwt_identity()

    event = UnknownEvent.query.filter_by(
        id=event_id,
        user_id=current_user_id
    ).first()

    if not event:
        return jsonify({"error": "Event not found"}), 404

    event.status = "dismissed"
    db.session.commit()

    return jsonify({
        "message": "Event dismissed successfully"
    }), 200