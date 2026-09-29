"""
RansomShield AI — Request Body Size Limit Middleware
Phase 5: Production Hardening & Resource Protection

Protects the FastAPI backend against memory exhaustion and denial-of-service
from oversized HTTP request payloads.
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status

from backend.config.settings import get_settings

logger = logging.getLogger("RansomShieldBackend.RequestSize")


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests exceeding the configured maximum body size limit with HTTP 413.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        settings = getattr(request.app.state, "settings", None) or get_settings()
        max_bytes = settings.max_request_body_bytes

        # 1. Inspect Content-Length header if present
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length_val = int(content_length)
                if length_val > max_bytes:
                    request_id = getattr(request.state, "request_id", None)
                    logger.warning(
                        f"[PAYLOAD_TOO_LARGE] Request on {request.url.path} exceeded Content-Length limit: "
                        f"{length_val} > {max_bytes} bytes"
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "success": False,
                            "data": None,
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds the maximum permitted size of {max_bytes // (1024 * 1024)}MB.",
                                "request_id": request_id,
                            },
                            "request_id": request_id,
                        },
                    )
            except ValueError:
                pass

        # 2. Wrap receive to protect against streaming / chunked oversized payloads
        original_receive = request.receive
        received_bytes = 0

        async def limited_receive():
            nonlocal received_bytes
            message = await original_receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received_bytes += len(body)
                if received_bytes > max_bytes:
                    logger.warning(
                        f"[PAYLOAD_TOO_LARGE] Streaming request on {request.url.path} exceeded body limit of {max_bytes} bytes"
                    )
                    raise MaxBodySizeExceededError(f"Request body exceeded {max_bytes} bytes limit.")
            return message

        request._receive = limited_receive

        try:
            return await call_next(request)
        except MaxBodySizeExceededError as e:
            request_id = getattr(request.state, "request_id", None)
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "data": None,
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": str(e),
                        "request_id": request_id,
                    },
                    "request_id": request_id,
                },
            )


class MaxBodySizeExceededError(Exception):
    """Raised when streaming request body exceeds maximum allowed size."""
    pass
