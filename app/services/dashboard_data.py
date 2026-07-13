"""Dashboard data queries mapped to the deployed firewall_logs schema."""

import ipaddress
from collections import Counter
from datetime import datetime

from sqlalchemy import func

from app import db
from app.models import BlacklistEntry, FirewallLog, HardwareMetric, UnknownEvent, User

PROTOCOL_NAMES = {0: "OTHER", 1: "ICMP", 6: "TCP", 17: "UDP"}

ACTION_DISPLAY = {
    "blocked": "BLOCK",
    "allowed": "ALLOW",
    "warned": "WARN",
}


def _is_known_model(model):
    if model is None:
        return False
    name = str(model).strip()
    return bool(name) and name.lower() != "unknown model"


def _known_model_logs_query():
    return FirewallLog.query.filter(
        FirewallLog.selected_model.isnot(None),
        FirewallLog.selected_model != "",
        func.lower(FirewallLog.selected_model) != "unknown model",
    )


def _format_ip(value):
    return value or "0.0.0.0"
def _format_action(action):
    if not action:
        return "ALLOW"
    return ACTION_DISPLAY.get(action.lower(), action.upper())


def _format_timestamp(value):
    if value is None:
        return "N/A"
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def serialize_log_row(log):
    """Shape expected by the Version Four dashboard templates."""
    return {
        "id": log.id,
        "src_ip": _format_ip(log.src_ip),
        "dst_ip": _format_ip(log.dst_ip),
        "selected_model": log.selected_model or "",
        "top_threat_type": log.threat_type or "BENIGN",
        "max_attack_prob": float(log.selected_score or 0.0),
        "action_taken": _format_action(log.action),
    }


def get_recent_logs():
    logs = _known_model_logs_query().order_by(FirewallLog.id.desc()).all()
    return [serialize_log_row(log) for log in logs]


def get_log_for_analysis(log_id):
    log = FirewallLog.query.get(log_id)
    if not log:
        return None
    row = serialize_log_row(log)
    user = User.query.get(log.user_id)
    row.update(
        {
            "timestamp": _format_timestamp(log.created_at),
            "username": user.username if user else "Unknown Account",
            "protocol": PROTOCOL_NAMES.get(log.protocol, str(log.protocol or "N/A")),
            "packet_size": log.size_bytes or 0,
            "duration": log.duration if log.duration is not None else "N/A",
            "fwd_pkts": log.fwd_pkts if log.fwd_pkts is not None else "N/A",
            "bwd_pkts": log.bwd_pkts if log.bwd_pkts is not None else "N/A",
            "fwd_rate": log.fwd_rate if log.fwd_rate is not None else "N/A",
        }
    )
    return row


def get_chart_data():
    known_logs = _known_model_logs_query()
    total_logs = known_logs.count()
    blocked_threats = known_logs.filter(
        FirewallLog.action.in_(["blocked", "warned"])
    ).count()

    distribution = (
        db.session.query(
            FirewallLog.selected_model,
            func.count(FirewallLog.id).label("volume"),
            func.avg(FirewallLog.selected_score).label("avg_prob"),
        )
        .filter(
            FirewallLog.selected_model.isnot(None),
            FirewallLog.selected_model != "",
            func.lower(FirewallLog.selected_model) != "unknown model",
        )
        .group_by(FirewallLog.selected_model)
        .order_by(func.count(FirewallLog.id).desc())
        .all()
    )

    model_labels = []
    model_counts = []
    prob_values = []

    for row in distribution:
        if not _is_known_model(row.selected_model):
            continue
        model_labels.append(str(row.selected_model))
        model_counts.append(int(row.volume))
        prob_values.append(float(row.avg_prob or 0.0))

    if not model_labels:
        model_labels = ["No Model Data"]
        model_counts = [0]
        prob_values = [0.0]

    timeline_rows = (
        _known_model_logs_query()
        .order_by(FirewallLog.created_at.desc())
        .limit(50)
        .all()
    )
    timeline_rows.reverse()

    scatter_points = []
    for log in timeline_rows:
        if log.created_at:
            scatter_points.append(
                {
                    "x": log.created_at.strftime("%H:%M:%S"),
                    "y": float(log.selected_score or 0.0) * 100,
                    "threat": str(log.threat_type or "Unknown"),
                    "ip": str(log.src_ip or "0.0.0.0"),
                }
            )

    return {
        "metrics": {"total_logs": total_logs, "blocked_threats": blocked_threats},
        "charts": {
            "labels": model_labels,
            "counts": model_counts,
            "probabilities": prob_values,
            "scatter_points": scatter_points,
        },
    }


def get_mobile_chat_context(user_id):
    """Build firewall log context for the mobile chatbot (scoped to one user)."""
    user_data = get_user_chatbot_metrics(user_id)
    if not user_data:
        return None

    logs = (
        FirewallLog.query.filter_by(user_id=user_id)
        .order_by(FirewallLog.id.desc())
        .limit(50)
        .all()
    )

    metrics = user_data["metrics"]
    lines = [
        f"Account: {user_data['username']} (user_id={user_id})",
        (
            f"Summary — total packets: {metrics['total_packets']}, "
            f"blocked: {metrics['blocked_packets']}, "
            f"highest threat score: {float(metrics['max_probability'] or 0) * 100:.1f}%, "
            f"most frequent threat: {metrics['top_threat_type']}, "
            f"unique destination ports: {metrics['unique_destinations']}"
        ),
        "",
        "Recent firewall events (newest first):",
    ]

    if not logs:
        lines.append("No firewall logs on record for this account.")
    else:
        for log in logs:
            row = serialize_log_row(log)
            prob_pct = f"{float(row['max_attack_prob']) * 100:.1f}%"
            lines.append(
                f"- Log {row['id']}: {row['src_ip']} -> {row['dst_ip']} | "
                f"Model: {row['selected_model']} | Threat: {row['top_threat_type']} ({prob_pct}) | "
                f"Action: {row['action_taken']}"
            )

    return "\n".join(lines)


def get_dashboard_chatbot_context():
    logs = FirewallLog.query.order_by(FirewallLog.id.desc()).limit(100).all()
    return [serialize_log_row(log) for log in logs]


def get_non_admin_users():
    return (
        User.query.filter_by(is_admin=False).order_by(User.id.asc()).all()
    )


def get_user_profile(user_id):
    return User.query.get(user_id)


def get_user_logs(user_id):
    user = User.query.get(user_id)
    if not user:
        return None

    logs = (
        FirewallLog.query.filter_by(user_id=user_id)
        .order_by(FirewallLog.id.desc())
        .all()
    )

    allow_count = 0
    block_count = 0
    size_buckets = {"Small (<150B)": 0, "Medium (150B-1KB)": 0, "Large (>1KB)": 0}

    serialized_logs = []
    for log in logs:
        action = _format_action(log.action)
        if action == "ALLOW":
            allow_count += 1
        elif action == "BLOCK":
            block_count += 1

        packet_size = int(log.size_bytes or 0)
        if packet_size < 150:
            size_buckets["Small (<150B)"] += 1
        elif packet_size <= 1024:
            size_buckets["Medium (150B-1KB)"] += 1
        else:
            size_buckets["Large (>1KB)"] += 1

        serialized_logs.append(
            {
                "id": log.id,
                "timestamp": _format_timestamp(log.created_at),
                "src_ip": _format_ip(log.src_ip),
                "dst_ip": _format_ip(log.dst_ip),
                "packet_size": log.size_bytes,
                "action_taken": action,
                "top_threat_type": log.threat_type,
                "max_attack_prob": float(log.selected_score or 0.0),
            }
        )

    return {
        "username": user.username,
        "logs": serialized_logs,
        "metrics": {
            "actions": [allow_count, block_count],
            "sizes": list(size_buckets.values()),
            "size_labels": list(size_buckets.keys()),
        },
    }


def get_user_chatbot_metrics(user_id):
    user = User.query.get(user_id)
    if not user:
        return None

    logs = FirewallLog.query.filter_by(user_id=user_id).all()
    if not logs:
        return {
            "username": user.username,
            "metrics": {
                "total_packets": 0,
                "blocked_packets": 0,
                "max_probability": 0.0,
                "top_threat_type": "None Detected",
                "unique_destinations": 0,
            },
        }

    blocked = sum(1 for log in logs if log.action == "blocked")
    max_prob = max(float(log.selected_score or 0.0) for log in logs)
    threat_counts = Counter(log.threat_type or "Unknown" for log in logs)
    top_threat = threat_counts.most_common(1)[0][0] if threat_counts else "None Detected"
    unique_dsts = len({log.dst_port for log in logs if log.dst_port is not None})

    return {
        "username": user.username,
        "metrics": {
            "total_packets": len(logs),
            "blocked_packets": blocked,
            "max_probability": max_prob,
            "top_threat_type": top_threat,
            "unique_destinations": unique_dsts,
        },
    }


def get_user_hardware(user_id):
    metrics = (
        HardwareMetric.query.filter_by(user_id=user_id)
        .order_by(HardwareMetric.recorded_at.desc())
        .all()
    )
    result = []
    for metric in metrics:
        recorded_at = metric.recorded_at
        if isinstance(recorded_at, datetime):
            recorded_at = recorded_at.strftime("%Y-%m-%d %H:%M:%S")
        result.append(
            {
                "id": metric.id,
                "user_id": metric.user_id,
                "cpu_usage": metric.cpu_usage,
                "ram_used_mb": metric.ram_used_mb,
                "ram_total_mb": metric.ram_total_mb,
                "battery_level": metric.battery_level,
                "recorded_at": recorded_at,
            }
        )
    return result


def get_fleet_topology():
    subquery = (
        db.session.query(
            HardwareMetric.user_id,
            func.max(HardwareMetric.recorded_at).label("latest"),
        )
        .group_by(HardwareMetric.user_id)
        .subquery()
    )

    rows = (
        db.session.query(HardwareMetric, User.username)
        .join(User, HardwareMetric.user_id == User.id)
        .join(
            subquery,
            (HardwareMetric.user_id == subquery.c.user_id)
            & (HardwareMetric.recorded_at == subquery.c.latest),
        )
        .all()
    )

    fleet = []
    for metric, username in rows:
        traffic = (
            db.session.query(func.coalesce(func.sum(FirewallLog.size_bytes), 0))
            .filter(FirewallLog.user_id == metric.user_id)
            .scalar()
        )
        fleet.append(
            {
                "user_id": metric.user_id,
                "username": username,
                "cpu_usage": metric.cpu_usage,
                "ram_used_mb": metric.ram_used_mb,
                "ram_total_mb": metric.ram_total_mb,
                "battery_level": metric.battery_level,
                "total_traffic": int(traffic or 0),
            }
        )
    return fleet


def get_user_fleet_snapshot(user_id):
    latest = (
        HardwareMetric.query.filter_by(user_id=user_id)
        .order_by(HardwareMetric.recorded_at.desc())
        .first()
    )
    if not latest:
        return None

    user = User.query.get(user_id)
    traffic = (
        db.session.query(func.coalesce(func.sum(FirewallLog.size_bytes), 0))
        .filter(FirewallLog.user_id == user_id)
        .scalar()
    )
    return {
        "user_id": latest.user_id,
        "username": user.username if user else "Unknown",
        "cpu_usage": latest.cpu_usage,
        "ram_used_mb": latest.ram_used_mb,
        "ram_total_mb": latest.ram_total_mb,
        "battery_level": latest.battery_level,
        "total_traffic": int(traffic or 0),
    }


def _extract_bf_dos(scores):
    """Derive legacy bf/dos scores from all_model_scores for UI compatibility."""
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
            elif "dos" in name or "hulk" in name or "loic" in name or "hoic" in name:
                dos = max(dos, val)
    return bf, dos


def serialize_unknown_event(event, username=None):
    bf_score, dos_score = _extract_bf_dos(event.all_model_scores)
    # Fall back to selected_score when model-keyed scores are absent.
    if bf_score == 0.0 and dos_score == 0.0 and event.selected_score is not None:
        selected = float(event.selected_score)
        model_name = str(event.selected_model or "").lower()
        if "bf" in model_name or "brute" in model_name:
            bf_score = selected
        else:
            dos_score = selected

    return {
        "id": event.id,
        "user_id": event.user_id,
        "username": username,
        "src_ip": event.src_ip or "N/A",
        "dst_ip": event.dst_ip or "N/A",
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": PROTOCOL_NAMES.get(event.protocol, str(event.protocol or "N/A")),
        "size_bytes": event.size_bytes or 0,
        "duration": event.duration,
        "fwd_pkts": event.fwd_pkts,
        "bwd_pkts": event.bwd_pkts,
        "fwd_rate": event.fwd_rate,
        "selected_model": event.selected_model or "",
        "selected_score": float(event.selected_score or 0.0),
        "all_model_scores": event.all_model_scores or {},
        "threat_type": event.threat_type or "—",
        # Legacy aliases kept for the existing unknown_events.html UI.
        "bf_score": bf_score,
        "dos_score": dos_score,
        "status": event.status or "pending",
        "label": event.label or "—",
        "created_at": _format_timestamp(event.created_at),
    }


def get_unknown_events_user_summary():
    users = User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()
    summary = []
    for user in users:
        count = UnknownEvent.query.filter_by(user_id=user.id).count()
        summary.append(
            {
                "id": user.id,
                "username": user.username,
                "event_count": count,
            }
        )
    summary.sort(key=lambda row: row["event_count"], reverse=True)
    return summary


def get_unknown_events_by_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return None

    events = (
        UnknownEvent.query.filter_by(user_id=user_id)
        .order_by(UnknownEvent.id.desc())
        .all()
    )
    return {
        "username": user.username,
        "user_id": user.id,
        "events": [serialize_unknown_event(event, user.username) for event in events],
    }


def get_unknown_event_for_analysis(event_id):
    event = UnknownEvent.query.get(event_id)
    if not event:
        return None
    user = User.query.get(event.user_id)
    return serialize_unknown_event(event, user.username if user else "Unknown")


def get_unknown_events_analysis_context(user_id):
    payload = get_unknown_events_by_user(user_id)
    if not payload:
        return None

    events = payload["events"]
    if not events:
        return {
            "username": payload["username"],
            "user_id": user_id,
            "context": "No unknown events on record for this account.",
        }

    lines = [
        f"Account: {payload['username']} (user_id={user_id})",
        f"Total unknown events: {len(events)}",
        "",
        "Unknown event records (ambiguous scores between warn and block thresholds):",
    ]
    for event in events[:100]:
        lines.append(
            f"- Event {event['id']}: {event['src_ip']}:{event['src_port'] or '?'} -> "
            f"{event['dst_ip']}:{event['dst_port'] or '?'} | Protocol: {event['protocol']} | "
            f"Model: {event['selected_model'] or 'N/A'} | "
            f"Score: {event['selected_score']:.4f} | Threat: {event['threat_type']} | "
            f"Status: {event['status']} | Size: {event['size_bytes']}B | "
            f"Duration: {event['duration']} | Fwd pkts: {event['fwd_pkts']} | "
            f"Created: {event['created_at']}"
        )

    return {
        "username": payload["username"],
        "user_id": user_id,
        "context": "\n".join(lines),
    }


def add_ip_to_blacklist(
    ip,
    scope,
    user_id=None,
    selected_model=None,
    selected_score=None,
    all_model_scores=None,
    bf_score=None,
    dos_score=None,
    notes=None,
):
    """Add an IP to blacklist_entries for one user or all non-admin users."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP address"}

    if notes and len(notes) > 255:
        return {"ok": False, "error": "notes too long"}

    # Map legacy dashboard UI bf/dos scores into the live schema when needed.
    if all_model_scores is None and (bf_score is not None or dos_score is not None):
        all_model_scores = {}
        if bf_score is not None:
            all_model_scores["bruteForce"] = float(bf_score)
        if dos_score is not None:
            all_model_scores["dos"] = float(dos_score)

    if selected_score is None and isinstance(all_model_scores, dict) and all_model_scores:
        try:
            selected_score = max(float(v) for v in all_model_scores.values())
        except (TypeError, ValueError):
            selected_score = None

    if not selected_model and isinstance(all_model_scores, dict) and all_model_scores:
        try:
            selected_model = max(all_model_scores.items(), key=lambda item: float(item[1]))[0]
        except (TypeError, ValueError):
            selected_model = None

    if scope == "global":
        target_ids = [user.id for user in User.query.filter_by(is_admin=False).all()]
    elif scope == "user":
        if not user_id:
            return {"ok": False, "error": "user_id is required when scope is user"}
        user = User.query.get(user_id)
        if not user:
            return {"ok": False, "error": "User not found"}
        target_ids = [user_id]
    else:
        return {"ok": False, "error": "scope must be 'user' or 'global'"}

    if not target_ids:
        return {"ok": False, "error": "No users available for blacklist"}

    added_user_ids = []
    skipped_user_ids = []

    for uid in target_ids:
        existing = BlacklistEntry.query.filter_by(user_id=uid, ip=ip).first()
        if existing:
            skipped_user_ids.append(uid)
            continue

        db.session.add(
            BlacklistEntry(
                user_id=uid,
                ip=ip,
                reason="manual",
                selected_model=selected_model,
                selected_score=selected_score,
                all_model_scores=all_model_scores,
                notes=notes,
            )
        )
        added_user_ids.append(uid)

    db.session.commit()

    return {
        "ok": True,
        "ip": ip,
        "scope": scope,
        "added_count": len(added_user_ids),
        "skipped_count": len(skipped_user_ids),
        "added_user_ids": added_user_ids,
        "skipped_user_ids": skipped_user_ids,
    }
