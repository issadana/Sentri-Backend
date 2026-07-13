from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from app.utils.decorators import admin_required
from app.services import dashboard_data as data


dashboard_api_bp = Blueprint("dashboard_api", __name__, url_prefix="/dashboard/api")


@dashboard_api_bp.route("/logs", methods=["GET"])
@jwt_required()
@admin_required
def admin_recent_logs():
    try:
        logs = data.get_recent_logs()
        return jsonify({"status": "success", "data": logs}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/logs/user/<int:user_id>", methods=["GET"])
@jwt_required()
@admin_required
def user_recent_logs(user_id):
    try:
        payload = data.get_user_logs(user_id)
        if not payload:
            return jsonify({"status": "error", "message": "No logs or user data found."}), 404
        return jsonify({"status": "success", **payload}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/chart-data", methods=["GET"])
@jwt_required()
@admin_required
def chart_data():
    try:
        chart_data_dict = data.get_chart_data()
        if not chart_data_dict:
            return jsonify({"status": "error", "message": "No chart data available."}), 404
        return jsonify(
            {
                "status": "success",
                "metrics": chart_data_dict["metrics"],
                "charts": chart_data_dict["charts"],
            }
        ), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/users-list", methods=["GET"])
@jwt_required()
@admin_required
def users_list():
    try:
        app_users = data.get_non_admin_users()
        live_profiles = []
        for row in app_users:
            live_profiles.append(
                {
                    "username": row.username,
                    "role": "admin" if row.is_admin else "user",
                    "risk": "SECURE",
                    "id": row.id,
                }
            )
        return jsonify({"status": "success", "data": live_profiles}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/hardware/<int:user_id>", methods=["GET"])
@jwt_required()
@admin_required
def user_hardware(user_id):
    try:
        hardware_history = data.get_user_hardware(user_id)
        if not hardware_history:
            return jsonify({"status": "success", "latest": None, "history": []}), 200
        return jsonify(
            {
                "status": "success",
                "latest": hardware_history[0],
                "history": hardware_history,
            }
        ), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/fleet", methods=["GET"])
@jwt_required()
@admin_required
def fleet_topology():
    try:
        fleet_data = data.get_fleet_topology()
        return jsonify({"status": "success", "fleet": fleet_data}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/unknown-events/users", methods=["GET"])
@jwt_required()
@admin_required
def unknown_events_users():
    try:
        summary = data.get_unknown_events_user_summary()
        return jsonify({"status": "success", "data": summary}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/unknown-events/user/<int:user_id>", methods=["GET"])
@jwt_required()
@admin_required
def unknown_events_by_user(user_id):
    try:
        payload = data.get_unknown_events_by_user(user_id)
        if not payload:
            return jsonify({"status": "error", "message": "User not found."}), 404
        return jsonify({"status": "success", **payload}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_api_bp.route("/unknown-events/blacklist", methods=["POST"])
@jwt_required()
@admin_required
def add_unknown_event_to_blacklist():
    try:
        body = request.get_json() or {}
        ip = (body.get("ip") or "").strip()
        scope = (body.get("scope") or "").strip().lower()
        user_id = body.get("user_id")
        bf_score = body.get("bf_score")
        dos_score = body.get("dos_score")
        selected_model = body.get("selected_model")
        selected_score = body.get("selected_score")
        all_model_scores = body.get("all_model_scores")
        notes = body.get("notes")

        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400

        result = data.add_ip_to_blacklist(
            ip=ip,
            scope=scope,
            user_id=user_id,
            selected_model=selected_model,
            selected_score=selected_score,
            all_model_scores=all_model_scores,
            bf_score=bf_score,
            dos_score=dos_score,
            notes=notes,
        )

        if not result.get("ok"):
            return jsonify({"status": "error", "message": result.get("error", "Failed to blacklist IP.")}), 400

        if result["added_count"] == 0:
            return jsonify({
                "status": "success",
                "message": "IP was already blacklisted for the selected scope.",
                "data": result,
            }), 200

        return jsonify({
            "status": "success",
            "message": f"IP blacklisted for {result['added_count']} user(s).",
            "data": result,
        }), 201
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


