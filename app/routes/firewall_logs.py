import json
import time
import ipaddress
from datetime import datetime, timezone
from threading import Lock

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt,
    verify_jwt_in_request,
)
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import PyJWTError

from app import db, sock
from app.models import FirewallLog, BlacklistEntry, UnknownEvent, UserSettings


firewall_logs_bp = Blueprint(
    "firewall_logs",
    __name__,
    url_prefix="/firewall-logs"
)


# --------------------------------------------------------------------------- #
# Contract constants (see docs/DATABASE_SCHEMA.md and the WS implementation
# notes). The Flutter client speaks this exact protocol.
# --------------------------------------------------------------------------- #
ALLOWED_ACTIONS = {"blocked", "warned", "allowed"}
ALLOWED_PROTOCOLS = {0, 1, 6, 17}

MAX_BATCH = 100                 # logs per log_batch message
MAX_MESSAGE_BYTES = 128 * 1024  # 128 KB per WS frame
RATE_LIMIT = 5                  # log_batch messages ...
RATE_WINDOW = 1.0               # ... per this many seconds, per connection
IDLE_TIMEOUT = 300              # seconds with no message before we close (1000)

# WebSocket close codes.
WS_NORMAL = 1000
WS_POLICY = 1008        # auth failure / rate limit
WS_TOO_BIG = 1009       # message exceeds MAX_MESSAGE_BYTES

# String field length caps.
_MAXLEN = {
    "selected_model": 100,
    "threat_type": 50,
    "service_name": 100,
    "app_name": 100,
    "app_package": 200,
}


# --------------------------------------------------------------------------- #
# Per-user socket registry (best effort, per worker process). Lets us push
# blacklist_update / settings_update frames to every live socket of a user,
# including the same user connected from two devices on this worker.
# --------------------------------------------------------------------------- #
_user_sockets = {}          # str(user_id) -> set(ws)
_registry_lock = Lock()


def _register(user_id, ws):
    with _registry_lock:
        _user_sockets.setdefault(str(user_id), set()).add(ws)


def _unregister(user_id, ws):
    with _registry_lock:
        sockets = _user_sockets.get(str(user_id))
        if sockets:
            sockets.discard(ws)
            if not sockets:
                _user_sockets.pop(str(user_id), None)


def _push_to_user(user_id, payload):
    """Send a JSON payload to every live socket of the given user (this worker)."""
    with _registry_lock:
        sockets = list(_user_sockets.get(str(user_id), ()))
    message = json.dumps(payload)
    for ws in sockets:
        try:
            ws.send(message)
        except Exception:
            # A dead socket will be cleaned up by its own handler on disconnect.
            pass


# --------------------------------------------------------------------------- #
# Validation / building
# --------------------------------------------------------------------------- #
def _clip(value, maxlen):
    """Strip a string field and enforce a maximum length; None-safe."""
    if value is None:
        return None
    text = str(value).strip()
    return text[:maxlen]


def _coerce_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError("expected an integer")


def _coerce_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ValueError("expected a number")


def _parse_created_at(value):
    """Parse the device ISO-8601 timestamp; fall back to server now() on miss."""
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _extract_bf_dos(scores):
    """Pull brute-force / DoS scores out of an all_model_scores object."""
    bf = 0.0
    dos = 0.0
    if isinstance(scores, dict):
        for key, raw in scores.items():
            try:
                val = float(raw)
            except (TypeError, ValueError):
                continue
            name = str(key).lower()
            if "bf" in name or "brute" in name:
                bf = max(bf, val)
            elif "dos" in name:
                dos = max(dos, val)
    return bf, dos


def _build_log(user_id, data):
    """
    Validate one wire-format log object and return an unsaved FirewallLog.

    Raises ValueError (mapped to the ``invalid_log`` error code) when a hard
    constraint from §6 is violated. String-length overflows are sanitized
    (stripped + truncated) rather than rejected.
    """
    if not isinstance(data, dict):
        raise ValueError("log must be an object")

    action = data.get("action")
    if action not in ALLOWED_ACTIONS:
        raise ValueError("action must be one of blocked|warned|allowed")

    protocol = data.get("protocol")
    if protocol is not None:
        protocol = _coerce_int(protocol)
        if protocol not in ALLOWED_PROTOCOLS:
            raise ValueError("protocol must be 0, 1, 6, 17 or null")

    src_ip = data.get("src_ip")
    if src_ip:
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            raise ValueError("src_ip is not a valid IP address")

    dst_ip = data.get("dst_ip")
    if dst_ip:
        try:
            ipaddress.ip_address(dst_ip)
        except ValueError:
            raise ValueError("dst_ip is not a valid IP address")

    selected_score = data.get("selected_score")
    if selected_score is not None:
        try:
            selected_score = float(selected_score)
        except (TypeError, ValueError):
            raise ValueError("selected_score must be a number")
        if not 0.0 <= selected_score <= 1.0:
            raise ValueError("selected_score must be in [0, 1]")

    scores = data.get("all_model_scores")
    if scores is not None:
        if not isinstance(scores, dict):
            raise ValueError("all_model_scores must be an object")
        for key, raw in scores.items():
            try:
                val = float(raw)
            except (TypeError, ValueError):
                raise ValueError("all_model_scores values must be numbers")
            if not 0.0 <= val <= 1.0:
                raise ValueError("all_model_scores values must be in [0, 1]")

    return FirewallLog(
        user_id=int(user_id),
        src_ip=(src_ip or None),
        dst_ip=(dst_ip or None),
        src_port=_coerce_int(data.get("src_port")),
        dst_port=_coerce_int(data.get("dst_port")),
        protocol=protocol,
        size_bytes=_coerce_int(data.get("size_bytes")),
        duration=_coerce_float(data.get("duration")),
        fwd_pkts=_coerce_int(data.get("fwd_pkts")),
        bwd_pkts=_coerce_int(data.get("bwd_pkts")),
        fwd_rate=_coerce_float(data.get("fwd_rate")),
        selected_model=_clip(data.get("selected_model"), _MAXLEN["selected_model"]),
        selected_score=selected_score,
        all_model_scores=scores,
        action=action,
        threat_type=_clip(data.get("threat_type"), _MAXLEN["threat_type"]),
        service_name=_clip(data.get("service_name"), _MAXLEN["service_name"]),
        app_name=_clip(data.get("app_name"), _MAXLEN["app_name"]),
        app_package=_clip(data.get("app_package"), _MAXLEN["app_package"]),
        is_system=bool(data.get("is_system", False)),
        created_at=_parse_created_at(data.get("created_at")),
    )


# --------------------------------------------------------------------------- #
# Persistence (shared by the REST POST and the WebSocket batch handler)
# --------------------------------------------------------------------------- #
def _auto_blacklist(user_id, logs):
    """
    Blacklist each unique src_ip of a *blocked* log that isn't already listed
    for this user. Returns the list of blacklist_update payloads to broadcast.
    Entries are added to the current session but NOT committed here.
    """
    blocked = {}
    for log in logs:
        if log.action == "blocked" and log.src_ip:
            current = blocked.get(log.src_ip)
            if current is None or (log.selected_score or 0) > (current.selected_score or 0):
                blocked[log.src_ip] = log

    payloads = []
    for ip, log in blocked.items():
        exists = BlacklistEntry.query.filter_by(user_id=int(user_id), ip=ip).first()
        if exists:
            continue

        bf_score, dos_score = _extract_bf_dos(log.all_model_scores)
        reason = (log.threat_type or log.selected_model or "auto_ml")[:20]

        db.session.add(BlacklistEntry(
            user_id=int(user_id),
            ip=ip,
            reason=reason,
            bf_score=bf_score,
            dos_score=dos_score,
            notes="Auto-added from firewall log",
        ))
        payloads.append({
            "type": "blacklist_update",
            "action": "added",
            "ip": ip,
            "reason": reason,
            "bf_score": bf_score,
            "dos_score": dos_score,
        })

    return payloads


def _record_unknown_events(user_id, logs):
    """
    Optional §5.6 — for logs whose selected_score is ambiguous
    (warn_threshold < score <= block_threshold), queue an unknown_events row
    (status pending) for later review/training. Thresholds come from settings.
    """
    settings = UserSettings.query.filter_by(user_id=int(user_id)).first()
    if not settings:
        return

    warn = settings.warn_threshold
    block = settings.block_threshold

    for log in logs:
        score = log.selected_score
        if score is None:
            continue
        if warn < score <= block:
            bf_score, dos_score = _extract_bf_dos(log.all_model_scores)
            db.session.add(UnknownEvent(
                user_id=int(user_id),
                src_ip=log.src_ip,
                src_port=log.src_port,
                dst_port=log.dst_port,
                protocol=log.protocol,
                size_bytes=log.size_bytes,
                bf_score=bf_score,
                dos_score=dos_score,
                status="pending",
            ))


def _persist_batch(user_id, raw_logs):
    """
    Validate, bulk-insert and post-process a batch of wire-format logs in a
    single transaction. Returns the list of inserted ids. Pushes any
    blacklist_update frames to the user's live sockets after commit.

    Raises ValueError if any log fails validation (whole batch is skipped).
    """
    logs = [_build_log(user_id, item) for item in raw_logs]

    db.session.add_all(logs)
    db.session.flush()                       # populate ids
    ids = [log.id for log in logs]

    blacklist_payloads = _auto_blacklist(user_id, logs)
    _record_unknown_events(user_id, logs)

    db.session.commit()

    for payload in blacklist_payloads:
        _push_to_user(user_id, payload)

    return ids


# --------------------------------------------------------------------------- #
# REST write path (kept for tooling / back-compat; the app now writes via WS)
# --------------------------------------------------------------------------- #
@firewall_logs_bp.route("", methods=["POST"])
@jwt_required()
def create_firewall_log():
    """
    Create a single firewall log (wire-contract shape).
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
            - action
          properties:
            src_ip:
              type: string
              example: "185.220.101.5"
            dst_ip:
              type: string
              example: "10.0.0.4"
            src_port:
              type: integer
              example: 52341
            dst_port:
              type: integer
              example: 443
            protocol:
              type: integer
              example: 6
            size_bytes:
              type: integer
              example: 1460
            duration:
              type: number
              example: 0.734
            fwd_pkts:
              type: integer
              example: 12
            bwd_pkts:
              type: integer
              example: 9
            fwd_rate:
              type: number
              example: 16.35
            selected_model:
              type: string
              example: "BF_v1"
            selected_score:
              type: number
              example: 0.92
            all_model_scores:
              type: object
              example: {"BF_v1": 0.92, "DoS_Hulk": 0.12}
            action:
              type: string
              example: "blocked"
            threat_type:
              type: string
              example: "brute_force"
            created_at:
              type: string
              example: "2026-06-07T14:23:01.000Z"
    responses:
      201:
        description: Firewall log created
      400:
        description: Invalid data
    """
    current_user_id = get_jwt_identity()
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "payload must be a JSON object"}), 400

    try:
        ids = _persist_batch(current_user_id, [data])
    except ValueError as err:
        db.session.rollback()
        return jsonify({"error": str(err)}), 400
    except Exception:
        db.session.rollback()
        return jsonify({"error": "server error"}), 500

    return jsonify({"message": "Firewall log saved", "id": ids[0]}), 201


# --------------------------------------------------------------------------- #
# REST read path (paginated / filterable). Unchanged contract: every row
# includes id + created_at, which the client's FirewallLog.fromJson requires.
# --------------------------------------------------------------------------- #
def _serialize_log(log):
    return {
        "id": log.id,
        "user_id": log.user_id,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "protocol": log.protocol,
        "size_bytes": log.size_bytes,
        "duration": log.duration,
        "fwd_pkts": log.fwd_pkts,
        "bwd_pkts": log.bwd_pkts,
        "fwd_rate": log.fwd_rate,
        "selected_model": log.selected_model,
        "selected_score": log.selected_score,
        "all_model_scores": log.all_model_scores,
        "action": log.action,
        "threat_type": log.threat_type,
        "service_name": log.service_name,
        "app_name": log.app_name,
        "app_package": log.app_package,
        "is_system": log.is_system,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "received_at": log.received_at.isoformat() if log.received_at else None,
    }


@firewall_logs_bp.route("", methods=["GET"])
@jwt_required()
def get_firewall_logs():
    """
    Get firewall logs (paginated, filterable).
    ---
    tags:
      - Firewall Logs
    security:
      - Bearer: []
    parameters:
      - in: query
        name: limit
        type: integer
        example: 100
      - in: query
        name: offset
        type: integer
        example: 0
      - in: query
        name: action
        type: string
        example: blocked
      - in: query
        name: threat_type
        type: string
      - in: query
        name: service_name
        type: string
      - in: query
        name: app_name
        type: string
      - in: query
        name: from_date
        type: string
        example: "2026-06-01T00:00:00Z"
      - in: query
        name: to_date
        type: string
        example: "2026-06-30T23:59:59Z"
    responses:
      200:
        description: List of firewall logs
      401:
        description: Unauthorized
    """
    current_user_id = get_jwt_identity()

    query = FirewallLog.query.filter_by(user_id=int(current_user_id))

    action = request.args.get("action")
    if action:
        query = query.filter(FirewallLog.action == action)

    threat_type = request.args.get("threat_type")
    if threat_type:
        query = query.filter(FirewallLog.threat_type == threat_type)

    service_name = request.args.get("service_name")
    if service_name:
        query = query.filter(FirewallLog.service_name == service_name)

    app_name = request.args.get("app_name")
    if app_name:
        query = query.filter(FirewallLog.app_name == app_name)

    from_date = request.args.get("from_date")
    if from_date:
        try:
            query = query.filter(
                FirewallLog.created_at >= datetime.fromisoformat(
                    from_date.replace("Z", "+00:00"))
            )
        except ValueError:
            return jsonify({"error": "invalid from_date"}), 400

    to_date = request.args.get("to_date")
    if to_date:
        try:
            query = query.filter(
                FirewallLog.created_at <= datetime.fromisoformat(
                    to_date.replace("Z", "+00:00"))
            )
        except ValueError:
            return jsonify({"error": "invalid to_date"}), 400

    query = query.order_by(FirewallLog.created_at.desc())

    try:
        limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
    except ValueError:
        limit = 200
    try:
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        offset = 0

    logs = query.offset(offset).limit(limit).all()

    return jsonify([_serialize_log(log) for log in logs]), 200


# --------------------------------------------------------------------------- #
# WebSocket write path — wss://<host>/ws/logs?token=<access_jwt>
# --------------------------------------------------------------------------- #
def _reject(ws, code, error_code, message=None):
    """Send a final error frame (best effort) and close the socket."""
    try:
        payload = {"type": "error", "code": error_code}
        if message:
            payload["message"] = message
        ws.send(json.dumps(payload))
    except Exception:
        pass
    try:
        ws.close(code)
    except Exception:
        pass


@sock.route("/ws/logs")
def firewall_logs_ws(ws):
    """
    Real-time firewall-log write path.

    URL: wss://<host>/ws/logs?token=<access_jwt>

    The JWT is validated on the handshake (query param ``token`` or the
    ``Authorization: Bearer`` header). On missing/invalid/expired token the
    socket is closed with code 1008. See docs/DATABASE_SCHEMA.md / the WS
    implementation notes for the full message protocol.
    """
    # Authenticate before doing anything else. flask-sock has already upgraded
    # the connection, so an auth failure is expressed by closing with 1008.
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        token_exp = get_jwt().get("exp")
    except (JWTExtendedException, PyJWTError, Exception):
        try:
            ws.close(WS_POLICY)
        except Exception:
            pass
        return

    _register(user_id, ws)
    batch_times = []  # monotonic timestamps of recent log_batch messages

    try:
        while True:
            try:
                raw = ws.receive(timeout=IDLE_TIMEOUT)
            except Exception:
                # Connection closed by the client.
                break

            if raw is None:
                # Idle timeout (client pings every 25s so this only trips on a
                # dead peer) — close cleanly.
                try:
                    ws.close(WS_NORMAL)
                except Exception:
                    pass
                break

            # Mid-session token expiry → tell the client to refresh + reconnect.
            if token_exp and time.time() >= token_exp:
                _reject(ws, WS_POLICY, "token_expired")
                break

            size = len(raw) if isinstance(raw, (bytes, bytearray)) \
                else len(raw.encode("utf-8"))
            if size > MAX_MESSAGE_BYTES:
                _reject(ws, WS_TOO_BIG, "batch_too_large", "message exceeds 128 KB")
                break

            try:
                message = json.loads(raw)
            except (TypeError, ValueError):
                ws.send(json.dumps({"type": "error", "code": "invalid_log",
                                    "message": "invalid JSON"}))
                continue

            if not isinstance(message, dict):
                ws.send(json.dumps({"type": "error", "code": "invalid_log",
                                    "message": "message must be an object"}))
                continue

            msg_type = message.get("type")

            if msg_type == "ping":
                ws.send(json.dumps({"type": "pong"}))
                continue

            if msg_type != "log_batch":
                # Unknown message type — ignore quietly.
                continue

            # --- rate limit: RATE_LIMIT log_batch / RATE_WINDOW per connection ---
            now = time.monotonic()
            batch_times = [t for t in batch_times if now - t < RATE_WINDOW]
            batch_times.append(now)
            if len(batch_times) > RATE_LIMIT:
                _reject(ws, WS_POLICY, "rate_limited")
                break

            logs = message.get("logs")
            if not isinstance(logs, list) or not logs:
                ws.send(json.dumps({"type": "error", "code": "invalid_log",
                                    "message": "logs must be a non-empty array"}))
                continue

            if len(logs) > MAX_BATCH:
                ws.send(json.dumps({"type": "error", "code": "batch_too_large",
                                    "message": "max 100 logs per batch"}))
                continue

            try:
                ids = _persist_batch(user_id, logs)
            except ValueError as err:
                db.session.rollback()
                ws.send(json.dumps({"type": "error", "code": "invalid_log",
                                    "message": str(err)}))
                continue
            except Exception:
                db.session.rollback()
                ws.send(json.dumps({"type": "error", "code": "server_error"}))
                continue

            ws.send(json.dumps({"type": "ack", "count": len(ids), "ids": ids}))
    finally:
        _unregister(user_id, ws)
