import json


class SSEHelper:
    """Helpers for streaming LangChain output as Server-Sent Events (SSE)."""

    @staticmethod
    def sse_event(event: str, data: dict) -> str:
        """Format a single SSE frame."""
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    @staticmethod
    def sse_yield_data(main_chain, main_chain_input, config, buffer_size: int = 5):
        """
        Stream a LangChain runnable to the client as SSE frames.

        Emits an ``init`` frame, then batches streamed tokens into ``message``
        frames of ``buffer_size`` chunks, and finally an ``end`` frame. Any
        error raised mid-stream is surfaced as an ``error`` frame so the client
        can react instead of silently hanging.
        """
        yield SSEHelper.sse_event("init", {"status": "started"})

        buffer_array = []
        full_response = ""

        try:
            for chunk in main_chain.stream(main_chain_input, config=config):
                content = chunk.content if hasattr(chunk, "content") else str(chunk)
                if content:
                    buffer_array.append(content)
                    full_response += content

                    if len(buffer_array) >= buffer_size:
                        yield SSEHelper.sse_event(
                            "message", {"token": "".join(buffer_array)}
                        )
                        buffer_array = []

            if buffer_array:
                yield SSEHelper.sse_event("message", {"token": "".join(buffer_array)})

            yield SSEHelper.sse_event(
                "end", {"status": "completed", "response": full_response}
            )
        except Exception as exc:  # noqa: BLE001 - surface any streaming failure to the client
            yield SSEHelper.sse_event("error", {"message": str(exc)})
