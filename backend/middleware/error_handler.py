"""
RansomShield AI — Global Error Handler & Exception Middleware
Phase 3A: Backend Foundation

Translates HTTP exceptions, validation errors, state machine transition errors,
and unhandled server errors into standardized API error response envelopes.
"""

import logging
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException

from agent.detection.incident_manager import InvalidStateTransitionError

logger = logging.getLogger("RansomShieldBackend.Errors")


def register_exception_handlers(app: FastAPI) -> None:
    """Registers unified error response handlers across the FastAPI application."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            409: "CONFLICT",
            422: "UNPROCESSABLE_ENTITY",
        }
        error_code = code_map.get(exc.status_code, "HTTP_ERROR")

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": error_code,
                    "message": str(exc.detail),
                    "request_id": request_id,
                },
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id} if request_id else None,
        )

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR",
                    "message": str(exc.detail),
                    "request_id": request_id,
                },
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id} if request_id else None,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        errors = exc.errors()
        error_messages = [f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in errors]

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid request payload or parameters.",
                    "request_id": request_id,
                    "details": error_messages,
                },
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id} if request_id else None,
        )

    @app.exception_handler(InvalidStateTransitionError)
    async def state_transition_exception_handler(request: Request, exc: InvalidStateTransitionError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "INVALID_STATE_TRANSITION",
                    "message": str(exc),
                    "request_id": request_id,
                },
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id} if request_id else None,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.error(f"[UNHANDLED_EXCEPTION] [{request_id}] {request.method} {request.url.path}: {exc}", exc_info=True)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An internal server error occurred.",
                    "request_id": request_id,
                },
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id} if request_id else None,
        )
