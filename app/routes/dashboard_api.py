from flask import Blueprint, jsonify
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


