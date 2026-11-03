"""FastAPI dependencies shared by the routers."""

from functools import cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from zero_cool_api.db import get_session
from zero_cool_api.technologies import Technology, load_technologies


@cache
def get_technologies() -> list[Technology]:
    """FastAPI dependency: technologies from ``technologies.yaml`` (read once)."""
    return load_technologies()


SessionDep = Annotated[Session, Depends(get_session)]
TechnologiesDep = Annotated[list[Technology], Depends(get_technologies)]
