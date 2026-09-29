"""
RansomShield AI — FastAPI Application Entrypoint
Phase 3A: Backend Foundation

Initializes the FastAPI application, CORS middleware, request logging,
global error handling, database connection lifespan, and API v1 routing.
"""

from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config.settings import Settings, get_settings
from backend.logging.structured_logger import BackendLogger
from backend.database.mongodb import get_db_manager
from backend.middleware.request_logging import RequestLoggingMiddleware
from backend.middleware.request_size import RequestSizeLimitMiddleware
from backend.middleware.rate_limiter import RateLimiterMiddleware
from backend.middleware.error_handler import register_exception_handlers
from backend.api.v1.router import api_v1_router

logger = BackendLogger.get_logger("RansomShieldBackend.Main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager handling application startup and shutdown events."""
    settings = getattr(app.state, "settings", None) or get_settings()
    logger.info(f"[BACKEND_START] Starting {settings.app_name} v{settings.app_version} ({settings.environment})")
    
    # Initialize optional database connection
    db_mgr = get_db_manager(settings)
    await db_mgr.connect()
    
    yield
    
    # Clean shutdown
    logger.info(f"[BACKEND_STOP] Shutting down {settings.app_name}...")
    try:
        from backend.ws.manager import ws_manager
        await ws_manager.close_all()
    except Exception as e:
        logger.warning(f"[WS_SHUTDOWN_WARNING] Error closing WebSockets: {e}")

    await db_mgr.disconnect()
    logger.info("[BACKEND_STOPPED] Backend shutdown complete.")


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Application factory for RansomShield FastAPI backend."""
    app_settings = settings or get_settings()
    get_db_manager(app_settings)

    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        description="RansomShield AI — Advanced Ransomware Detection & SOC Monitoring Backend",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = app_settings

    # 1. Register Global Exception Handlers
    register_exception_handlers(app)

    # 2. Register Request Logging & Correlation ID Middleware
    app.add_middleware(RequestLoggingMiddleware)

    # 3. Register Rate Limiter Middleware (Sliding window per client IP)
    app.add_middleware(RateLimiterMiddleware)

    # 4. Register Request Body Size Limit Middleware (Protects against oversized bodies)
    app.add_middleware(RequestSizeLimitMiddleware)

    # 5. Register CORS Middleware
    cors_kwargs = {
        "allow_origins": app_settings.cors_origins,
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }
    if app_settings.environment != "production":
        cors_kwargs["allow_origin_regex"] = (
            r"^https?://(localhost|127\.0\.0\.1"
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})(:\d+)?$"
        )

    app.add_middleware(CORSMiddleware, **cors_kwargs)

    # 4. Mount API v1 Master Router
    app.include_router(api_v1_router, prefix=app_settings.api_v1_prefix)

    # 5. Root Info Route
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": app_settings.app_name,
            "version": app_settings.app_version,
            "environment": app_settings.environment,
            "docs": "/docs",
            "health": f"{app_settings.api_v1_prefix}/health",
        }

    return app


# Default application instance
app = create_app()
