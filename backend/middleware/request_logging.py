"""
RansomShield AI — Request Logging & Correlation ID Middleware
Phase 3A: Backend Foundation

Injects unique request correlation IDs (X-Request-ID) into all incoming HTTP requests
and logs structured request duration, status code, method, and route.
"""

import time
import uuid
import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("RansomShieldBackend.HTTP")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware generating request correlation IDs and logging HTTP request performance.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request-ID"] = request_id

            logger.info(
                f"[HTTP] [{request_id}] {request.method} {request.url.path} "
                f"-> {response.status_code} ({duration_ms}ms)"
            )
            return response
        except Exception as e:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"[HTTP_ERROR] [{request_id}] {request.method} {request.url.path} "
                f"-> 500 ({duration_ms}ms) — Error: {e}"
            )
            raise
