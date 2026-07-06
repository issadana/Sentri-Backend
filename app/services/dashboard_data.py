"""Mobile chat data queries mapped to the deployed firewall_logs schema."""

from collections import Counter

from app.models import FirewallLog, User

ACTION_DISPLAY = {
    "blocked": "BLOCK",
    "allowed": "ALLOW",
    "warned": "WARN",
}


def _format_dst(log):
    if log.dst_port is not None:
        return f"port:{log.dst_port}"
    return "N/A"


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


def get_mobile_chat_context(user_id):
    """Build a compact text context of the user's recent firewall activity for
    the mobile chat assistant. Returns None if the user does not exist."""
    user = User.query.get(user_id)
    if not user:
        return None

    logs = (
        FirewallLog.query.filter_by(user_id=user_id)
        .order_by(FirewallLog.id.desc())
        .limit(50)
        .all()
    )

    if not logs:
        return (
            f"Account: {user.username} (User ID: {user_id})\n"
            "No firewall activity has been recorded yet."
        )

    blocked = sum(1 for log in logs if log.action == "blocked")
    max_prob = max(float(log.selected_score or 0.0) for log in logs)
    threat_counts = Counter(log.threat_type or "Unknown" for log in logs)
    top_threat = threat_counts.most_common(1)[0][0] if threat_counts else "None Detected"
    unique_dsts = len({log.dst_port for log in logs if log.dst_port is not None})

    lines = [
        f"Account: {user.username} (User ID: {user_id})",
        f"Recent packets analyzed: {len(logs)}",
        f"Blocked/high-risk packets: {blocked}",
        f"Highest attack probability: {max_prob * 100:.1f}%",
        f"Most frequent threat type: {top_threat}",
        f"Unique destination ports contacted: {unique_dsts}",
        "",
        "Recent log records:",
    ]
    for log in logs[:15]:
        lines.append(
            f"- #{log.id} {_format_timestamp(log.created_at)} "
            f"src={log.src_ip or '0.0.0.0'} {_format_dst(log)} "
            f"threat={log.threat_type or 'BENIGN'} "
            f"prob={float(log.selected_score or 0.0) * 100:.1f}% "
            f"action={_format_action(log.action)}"
        )
    return "\n".join(lines)
