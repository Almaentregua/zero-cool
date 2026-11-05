"""FastAPI dependencies shared by the routers."""

from functools import cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from zero_cool_api.db import get_engine, get_session
from zero_cool_api.research.base import ResearchSource
from zero_cool_api.research.registry import build_sources
from zero_cool_api.research.runner import ResultCache
from zero_cool_api.technologies import Technology, load_technologies


@cache
def get_technologies() -> list[Technology]:
    """FastAPI dependency: technologies from ``technologies.yaml`` (read once)."""
    return load_technologies()


@cache
def get_research_sources() -> list[ResearchSource]:
    """FastAPI dependency: the research sources, created once per process.

    Sources hold their own HTTP client, rate limiter and memos, so they are shared.
    """
    engine = get_engine()
    return build_sources(lambda: Session(engine))


@cache
def get_result_cache() -> ResultCache:
    """FastAPI dependency: the in-memory cache shared by all investigations."""
    return ResultCache()


SessionDep = Annotated[Session, Depends(get_session)]
TechnologiesDep = Annotated[list[Technology], Depends(get_technologies)]
ResearchSourcesDep = Annotated[list[ResearchSource], Depends(get_research_sources)]
ResultCacheDep = Annotated[ResultCache, Depends(get_result_cache)]
