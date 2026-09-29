"""
RansomShield AI — In-Memory Sliding-Window Rate Limiter Middleware
Phase 5: Production Hardening & Resource Protection

Implements sliding-window request throttling per client IP address.
Differentiates sensitive endpoints (auth, response containment) from standard SOC telemetry.
"""

import time
import logging
from collections import defaultdict, deque
from typing import Dict, Deque
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status

from backend.config.settings import get_settings

logger = logging.getLogger("RansomShieldBackend.RateLimiter")


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window in-memory rate limiter per client IP.
    """

    def __init__(self, app):
        super().__init__(app)
        # Separate request history deques for categories: ip -> deque[timestamps]
        self._general_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._auth_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._response_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._window_seconds = 60.0

    def _get_client_ip(self, request: Request) -> str:
        """Extracts client IP, respecting X-Forwarded-For if behind a reverse proxy."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    def _check_rate_limit(self, bucket: Deque[float], max_requests: int, now: float) -> bool:
        """
        Prunes entries older than the sliding window and evaluates threshold.
        Returns True if request is ALLOWED, False if limit EXCEEDED.
        """
        cutoff = now - self._window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= max_requests:
            return False

        bucket.append(now)
        return True

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = getattr(request.app.state, "settings", None) or get_settings()

        # Skip rate limiting if disabled in settings or for static/docs routes
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Never rate limit CORS preflight OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        if path.startswith(("/docs", "/redoc", "/openapi.json", "/api/v1/health")):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.time()

        # Determine category and threshold
        if "/auth/login" in path or "/auth/register" in path:
            limit = settings.rate_limit_auth_per_minute
            bucket = self._auth_buckets[client_ip]
            category = "auth"
        elif "/response/actions" in path:
            limit = settings.rate_limit_response_per_minute
            bucket = self._response_buckets[client_ip]
            category = "response"
        else:
            limit = settings.rate_limit_general_per_minute
            bucket = self._general_buckets[client_ip]
            category = "general"

        if not self._check_rate_limit(bucket, limit, now):
            logger.warning(
                f"[RATE_LIMIT_EXCEEDED] Client IP '{client_ip}' exceeded {category} limit ({limit} req/min) on {path}"
            )
            request_id = getattr(request.state, "request_id", None)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "success": False,
                    "data": None,
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Rate limit exceeded. Maximum {limit} requests per minute for this endpoint.",
                        "request_id": request_id,
                    },
                    "request_id": request_id,
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        remaining = max(0, limit - len(bucket))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
