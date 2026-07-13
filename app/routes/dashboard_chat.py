import sys

from flask import Blueprint, jsonify, request, Response, stream_with_context
from flask_jwt_extended import jwt_required, get_jwt_identity
from langchain_community.chat_message_histories import ChatMessageHistory
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_ollama import ChatOllama

from app.services import dashboard_data as data
from app.utils.decorators import admin_required
from app.utils.prompts import Prompts
from app.utils.sse_helper import SSEHelper


dashboard_chat_bp = Blueprint("dashboard_chat", __name__)

prompts = Prompts()
_history = {}


def _get_session_history(session_id: str):
    if session_id not in _history:
        _history[session_id] = ChatMessageHistory()
    return _history[session_id]


def _get_llm():
    from config import Config

    if not Config.OLLAMA_BASE_URL:
        return None
    try:
        return ChatOllama(
            model=Config.OLLAMA_MODEL,
            temperature=0.2,
            base_url=Config.OLLAMA_BASE_URL,
        )
    except Exception as exc:
        print(f"Ollama initialization warning: {exc}", file=sys.stderr)
        return None


def analyze_fleet_with_llm(snapshot):
    llm = _get_llm()
    if not llm:
        return "NOVA AI module currently offline."
    chain = prompts.get_analyze_fleet_prompt() | llm | StrOutputParser()
    try:
        return chain.invoke({"data": str(snapshot)})
    except Exception:
        return "NOVA AI module currently offline."


def _llm_offline_response():
    return jsonify({"status": "error", "message": "Local ChatOllama engine is offline."}), 503


@dashboard_chat_bp.route("/dashboard/api/nova/analyze", methods=["POST"])
@jwt_required()
@admin_required
def analyze_fleet_node():
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    if not user_id:
        return jsonify({"insight": "No user_id provided."}), 400

    snapshot = data.get_user_fleet_snapshot(user_id)
    if not snapshot:
        return jsonify({"insight": "No data available for this user."}), 200

    return jsonify({"insight": analyze_fleet_with_llm(snapshot)}), 200


@dashboard_chat_bp.route("/api/analyze-log/<int:log_id>", methods=["POST"])
@jwt_required()
@admin_required
def analyze_log(log_id):
    try:
        log_entry = data.get_log_for_analysis(log_id)
        if not log_entry:
            return jsonify({"status": "error", "message": "Log target not found."}), 404

        llm = _get_llm()
        if not llm:
            return _llm_offline_response()

        prob_str = f"{float(log_entry['max_attack_prob']) * 100:.1f}%"
        chain = prompts.get_analyze_dashboard_log_prompt() | llm | StrOutputParser()
        analysis_report = chain.invoke(
            {
                "id": log_entry["id"],
                "src_ip": log_entry["src_ip"],
                "dst_ip": log_entry["dst_ip"],
                "threat_type": log_entry["top_threat_type"],
                "prob": prob_str,
                "action": log_entry["action_taken"],
            }
        )
        return jsonify({"status": "success", "analysis": analysis_report}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_chat_bp.route("/api/analyze_user_log/<int:log_id>", methods=["POST"])
@jwt_required()
@admin_required
def analyze_user_log(log_id):
    try:
        user_row_log = data.get_log_for_analysis(log_id)
        if not user_row_log:
            return jsonify({"status": "error", "message": "Log frame record not found."}), 404

        llm = _get_llm()
        if not llm:
            return _llm_offline_response()

        chain = prompts.get_analyze_user_log_prompt() | llm | StrOutputParser()
        ai_analysis = chain.invoke(
            {
                "log_id": user_row_log["id"],
                "timestamp": str(user_row_log["timestamp"]),
                "username": user_row_log.get("username") or "Unknown Account",
                "src_ip": user_row_log["src_ip"],
                "dst_ip": user_row_log["dst_ip"],
                "protocol": user_row_log["protocol"],
                "packet_size": user_row_log["packet_size"],
                "duration": user_row_log["duration"],
                "fwd_pkts": user_row_log["fwd_pkts"],
                "bwd_pkts": user_row_log["bwd_pkts"],
                "fwd_rate": user_row_log["fwd_rate"],
                "top_threat_type": user_row_log["top_threat_type"],
                "max_prob": float(user_row_log["max_attack_prob"] or 0.0) * 100,
                "action_taken": user_row_log["action_taken"],
            }
        )
        return jsonify({"status": "success", "analysis": ai_analysis}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_chat_bp.route("/api/chat-bot", methods=["GET"])
@jwt_required()
@admin_required
def chat_bot():
    llm = _get_llm()
    if not llm:
        return _llm_offline_response()

    user_message = request.args.get("message")
    session_id = request.args.get("session_id", "static_guest_session")
    if not user_message:
        return jsonify({"status": "error", "message": "Empty query received."}), 400

    try:
        current_logs = data.get_dashboard_chatbot_context()
        if current_logs:
            context_data_dump = ""
            for row in current_logs:
                prob_pct = f"{float(row['max_attack_prob']) * 100:.1f}%"
                context_data_dump += (
                    f"- Log ID {row['id']}: Source {row['src_ip']} -> Dest {row['dst_ip']} | "
                    f"Threat: {row['top_threat_type']} ({prob_pct} Prob) | "
                    f"Enforced Action: {row['action_taken']}\n"
                )
        else:
            context_data_dump = "No logs currently populated in database."

        chain = prompts.get_dashboard_chatbot_prompt() | llm
        chain_with_history = RunnableWithMessageHistory(
            chain,
            _get_session_history,
            input_messages_key="question",
            history_messages_key="history",
        )
        chain_input = {"table_context": context_data_dump, "question": user_message}
        config = {"configurable": {"session_id": session_id}}

        return Response(
            stream_with_context(
                SSEHelper.sse_yield_data(chain_with_history, chain_input, config)
            ),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_chat_bp.route("/api/chat-user/<int:user_id>", methods=["GET"])
@jwt_required()
@admin_required
def chat_user_scoped(user_id):
    llm = _get_llm()
    if not llm:
        return _llm_offline_response()

    user_prompt = request.args.get("prompt", "").strip()
    session_id = request.args.get("session_id", "static_guest_session")
    if not user_prompt:
        return jsonify({"status": "error", "message": "Prompt cannot be empty."}), 400

    try:
        user_chatbot_data = data.get_user_chatbot_metrics(user_id)
        if not user_chatbot_data:
            return jsonify({"status": "error", "message": "User not found."}), 404

        username = user_chatbot_data["username"]
        metrics = user_chatbot_data["metrics"]

        chain = prompts.get_user_chatbot_prompt() | llm
        chain_input = {
            "username": username,
            "user_id": user_id,
            "total_packets": metrics["total_packets"],
            "blocked_packets": metrics["blocked_packets"],
            "max_attack_prob": float(metrics["max_probability"] or 0.0) * 100,
            "top_threat_type": metrics["top_threat_type"],
            "unique_destinations": metrics["unique_destinations"],
            "question": user_prompt,
        }
        chain_with_history = RunnableWithMessageHistory(
            chain,
            _get_session_history,
            input_messages_key="question",
            history_messages_key="history",
        )
        config = {"configurable": {"session_id": session_id}}

        return Response(
            stream_with_context(
                SSEHelper.sse_yield_data(chain_with_history, chain_input, config)
            ),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_chat_bp.route("/api/analyze-unknown-event/<int:event_id>", methods=["POST"])
@jwt_required()
@admin_required
def analyze_unknown_event(event_id):
    try:
        event = data.get_unknown_event_for_analysis(event_id)
        if not event:
            return jsonify({"status": "error", "message": "Unknown event not found."}), 404

        llm = _get_llm()
        if not llm:
            return _llm_offline_response()

        chain = prompts.get_analyze_unknown_event_prompt() | llm | StrOutputParser()
        analysis = chain.invoke(
            {
                "event_id": event["id"],
                "username": event["username"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "src_port": event["src_port"] or "N/A",
                "dst_port": event["dst_port"] or "N/A",
                "protocol": event["protocol"],
                "size_bytes": event["size_bytes"],
                "selected_model": event["selected_model"] or "N/A",
                "selected_score": event["selected_score"],
                "threat_type": event["threat_type"],
                "all_model_scores": event["all_model_scores"] or {},
                "status": event["status"],
                "duration": event["duration"] if event["duration"] is not None else "N/A",
                "fwd_pkts": event["fwd_pkts"] if event["fwd_pkts"] is not None else "N/A",
                "bwd_pkts": event["bwd_pkts"] if event["bwd_pkts"] is not None else "N/A",
                "fwd_rate": event["fwd_rate"] if event["fwd_rate"] is not None else "N/A",
                "created_at": event["created_at"],
            }
        )
        return jsonify({"status": "success", "analysis": analysis}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_chat_bp.route("/dashboard/api/unknown-events/analyze/<int:user_id>", methods=["POST"])
@jwt_required()
@admin_required
def analyze_user_unknown_events(user_id):
    try:
        payload = data.get_unknown_events_analysis_context(user_id)
        if not payload:
            return jsonify({"status": "error", "message": "User not found."}), 404

        llm = _get_llm()
        if not llm:
            return _llm_offline_response()

        chain = prompts.get_analyze_user_unknown_events_prompt() | llm | StrOutputParser()
        analysis = chain.invoke({"events_context": payload["context"]})
        return jsonify(
            {
                "status": "success",
                "analysis": analysis,
                "username": payload["username"],
            }
        ), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
