import os

from flask import Blueprint, request, jsonify, Response, stream_with_context
from flask_jwt_extended import jwt_required
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

from app.utils.sse_helper import SSEHelper


chat_bp = Blueprint("chat", __name__, url_prefix="/api")


# Lazily build the Groq chat model once per process. Instantiating on first use
# (rather than at import time) keeps the app importable even if the API key is
# not configured in a given environment.
_mobile_llm = None


def _get_mobile_llm() -> ChatGroq:
    global _mobile_llm
    if _mobile_llm is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not configured.")
        _mobile_llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            temperature=0,
            max_tokens=None,
            timeout=None,
            max_retries=2,
            groq_api_key=api_key,
        )
    return _mobile_llm


@chat_bp.route("/mobile_chat", methods=["GET"])
@jwt_required()
def mobile_chat_func():
    """
Stream a chatbot reply over Server-Sent Events.

Stateless: each request is answered on its own with no conversation memory.
---
tags:
  - Chat
security:
  - Bearer: []
produces:
  - text/event-stream
parameters:
  - in: query
    name: prompt
    required: true
    type: string
    description: The user's message.
  - in: query
    name: token
    required: false
    type: string
    description: JWT access token, for clients (e.g. EventSource) that cannot set the Authorization header. Alternatively send it as "Authorization: Bearer <token>".
responses:
  200:
    description: SSE stream of init/message/end events.
  400:
    description: Prompt was empty.
  401:
    description: Missing or invalid JWT.
"""
    user_prompt = request.args.get("prompt", "").strip()

    if not user_prompt:
        return jsonify({"status": "error", "message": "Prompt cannot be empty."}), 400

    try:
        mobile_prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an AI assistant."),
            ("human", "{text}"),
        ])

        mobile_chain = mobile_prompt | _get_mobile_llm()

        mobile_chat_chain_input = {"text": user_prompt}

        return Response(
            stream_with_context(
                SSEHelper.sse_yield_data(mobile_chain, mobile_chat_chain_input, config=None)
            ),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    except Exception as e:
        return jsonify(
            {"status": "error", "message": f"LCEL pipeline generation error: {str(e)}"}
        ), 500
