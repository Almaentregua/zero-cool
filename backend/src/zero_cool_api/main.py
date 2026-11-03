"""FastAPI application entry point."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DEFAULT_CORS_ORIGINS = "http://localhost:5173"


class HealthResponse(BaseModel):
    """Response model for the health check endpoint."""

    status: str = Field(description="Service status.", examples=["ok"])


def get_cors_origins() -> list[str]:
    """Read the allowed CORS origins from the environment.

    Returns:
        Origins listed (comma separated) in ``CORS_ORIGINS``, or the Vite
        dev server origin when the variable is unset.
    """
    raw = os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app() -> FastAPI:
    """Build the FastAPI application.

    Returns:
        The configured application instance.
    """
    app = FastAPI(title="Zero Cool API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    @app.get(
        "/api/health",
        summary="Health check",
        description="Returns ok when the API is running. Used by the frontend and monitoring.",
        response_model=HealthResponse,
        responses={
            200: {
                "description": "Service is up.",
                "content": {"application/json": {"example": {"status": "ok"}}},
            }
        },
    )
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    return app


app = create_app()
