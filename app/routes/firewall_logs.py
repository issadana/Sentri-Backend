import json

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import PyJWTError
from datetime import datetime

from app import db, sock
from app.models import FirewallLog, BlacklistEntry


firewall_logs_bp = Blueprint(
    "firewall_logs",
    __name__,
    url_prefix="/firewall-logs"
)


def _persist_firewall_log(user_id, data):
    """
    Create a FirewallLog (and auto-blacklist the source IP when an entry is
    blocked) for the given user from a payload dict.

    Shared by the REST POST endpoint and the WebSocket endpoint so both accept
    exactly the same data. Raises ValueError when required fields are missing;
    callers are responsible for committing is handled here.
    """
    action_taken = data.get("action_taken")

    if not action_taken:
        raise ValueError("action_taken is required")

    log = FirewallLog(
        user_id=user_id,

        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        src_port=data.get("src_port"),
        dst_port=data.get("dst_port"),
        protocol=data.get("protocol"),

        packet_size=data.get("packet_size", 0),
        duration=data.get("duration", 0),

        iat_mean=data.get("iat_mean", 0),
        iat_std=data.get("iat_std", 0),

        fwd_pkts=data.get("fwd_pkts", 0),
        bwd_pkts=data.get("bwd_pkts", 0),

        fwd_max=data.get("fwd_max", 0),
        fwd_rate=data.get("fwd_rate", 0),
        fwd_mean=data.get("fwd_mean", 0),
        idle_mean=data.get("idle_mean", 0),

        pkt_size_avg=data.get("pkt_size_avg", 0),

        prob_brute=data.get("prob_brute", 0),
        prob_dos=data.get("prob_dos", 0),
        prob_adv_dos=data.get("prob_adv_dos", 0),
        prob_loic=data.get("prob_loic", 0),
        prob_hoic=data.get("prob_hoic", 0),

        top_threat_type=data.get("top_threat_type"),
        max_attack_prob=data.get("max_attack_prob", 0),

        action_taken=action_taken,
        all_model_scores=data.get("all_model_scores"),

        service_name=data.get("service_name"),
        app_name=data.get("app_name"),
        app_package=data.get("app_package"),
        is_system=data.get("is_system", False)
    )

    db.session.add(log)

    if action_taken == "blocked" and data.get("src_ip"):

        existing_blacklist = BlacklistEntry.query.filter_by(
            user_id=user_id,
            ip=data.get("src_ip")
        ).first()

        if not existing_blacklist:

            blacklist_entry = BlacklistEntry(
                user_id=user_id,
                ip=data.get("src_ip"),
                reason="auto_ml",
                bf_score=data.get("prob_brute", 0),
                dos_score=data.get("prob_dos", 0),
                notes="Automatically added from firewall log"
            )

            db.session.add(blacklist_entry)

    db.session.commit()

    return log


@firewall_logs_bp.route("", methods=["POST"])
@jwt_required()
def create_firewall_log():
    """
    Create firewall log.
    ---
    tags:
      - Firewall Logs
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
            - action_taken
          properties:
            src_ip:
              type: string
              example: "192.168.1.10"
            dst_ip:
              type: string
              example: "8.8.8.8"
            src_port:
              type: integer
              example: 443
            dst_port:
              type: integer
              example: 80
            protocol:
              type: string
              example: "TCP"
            packet_size:
              type: number
              example: 512
            duration:
              type: number
              example: 2.5
            action_taken:
              type: string
              example: "blocked"
    responses:
      201:
        description: Firewall log created
      400:
        description: Invalid data
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()

    try:
        log = _persist_firewall_log(current_user_id, data)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    return jsonify({
        "message": "Firewall log saved",
        "id": log.id
    }), 201


@firewall_logs_bp.route("", methods=["GET"])
@jwt_required()
def get_firewall_logs():
    """
    Get firewall logs.
    ---
    tags:
      - Firewall Logs
    security:
      - Bearer: []
    responses:
      200:
        description: List of firewall logs
      401:
        description: Unauthorized
    """
    current_user_id = get_jwt_identity()

    query = FirewallLog.query.filter_by(
        user_id=current_user_id
    )

    logs = query.order_by(
        FirewallLog.timestamp.desc()
    ).all()

    result = []

    for log in logs:
        result.append({
            "id": log.id,
            "user_id": log.user_id,
            "timestamp": log.timestamp,

            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "src_port": log.src_port,
            "dst_port": log.dst_port,
            "protocol": log.protocol,

            "packet_size": log.packet_size,
            "duration": log.duration,

            "iat_mean": log.iat_mean,
            "iat_std": log.iat_std,

            "fwd_pkts": log.fwd_pkts,
            "bwd_pkts": log.bwd_pkts,

            "fwd_max": log.fwd_max,
            "fwd_rate": log.fwd_rate,
            "fwd_mean": log.fwd_mean,
            "idle_mean": log.idle_mean,

            "pkt_size_avg": log.pkt_size_avg,

            "prob_brute": log.prob_brute,
            "prob_dos": log.prob_dos,
            "prob_adv_dos": log.prob_adv_dos,
            "prob_loic": log.prob_loic,
            "prob_hoic": log.prob_hoic,

            "top_threat_type": log.top_threat_type,
            "max_attack_prob": log.max_attack_prob,

            "action_taken": log.action_taken,
            "all_model_scores": log.all_model_scores,

            "service_name": log.service_name,
            "app_name": log.app_name,
            "app_package": log.app_package,
            "is_system": log.is_system
        })

    return jsonify(result), 200


@sock.route("/ws", bp=firewall_logs_bp)
def firewall_logs_ws(ws):
    """
    Secure WebSocket endpoint for streaming firewall logs.

    URL: wss://<host>/firewall-logs/ws

    Authentication (same JWT as the REST API) is required on the handshake and
    can be supplied either way:
      - Header:       Authorization: Bearer <access_token>   (native clients)
      - Query string: wss://<host>/firewall-logs/ws?token=<access_token>

    After connecting, send one JSON object per message containing exactly the
    same fields as the POST /firewall-logs body, e.g.:
      {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "protocol": "TCP",
       "action_taken": "blocked"}

    The server replies with a JSON object per message:
      {"message": "Firewall log saved", "id": 123}   on success
      {"error": "<reason>"}                           on failure
    """
    # Authenticate the upgrade request. verify_jwt_in_request() reads the token
    # from the locations configured in JWT_TOKEN_LOCATION (header or query
    # string) and raises if it is missing, malformed, or expired.
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
    except (JWTExtendedException, PyJWTError):
        ws.send(json.dumps({"error": "unauthorized"}))
        ws.close()
        return

    ws.send(json.dumps({"message": "connected", "user_id": user_id}))

    while True:
        raw = ws.receive()

        # receive() returns None when the client disconnects.
        if raw is None:
            break

        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            ws.send(json.dumps({"error": "invalid JSON"}))
            continue

        if not isinstance(data, dict):
            ws.send(json.dumps({"error": "payload must be a JSON object"}))
            continue

        try:
            log = _persist_firewall_log(user_id, data)
        except ValueError as err:
            db.session.rollback()
            ws.send(json.dumps({"error": str(err)}))
            continue
        except Exception:
            db.session.rollback()
            ws.send(json.dumps({"error": "internal error"}))
            continue

        ws.send(json.dumps({
            "message": "Firewall log saved",
            "id": log.id
        }))
