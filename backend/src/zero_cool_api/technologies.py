"""Loading and validation of ``technologies.yaml``.

Adding a technology is only adding an entry to the file; no code changes.
"""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

DEFAULT_TECHNOLOGIES_FILE = "technologies.yaml"


class Product(BaseModel):
    """A vendor/product pair as used by CISA KEV and NVD (lowercase)."""

    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)


class Technology(BaseModel):
    """A technology tracked by the app (e.g. Java)."""

    name: str = Field(min_length=1)
    osv_ecosystems: list[str] = Field(default_factory=list)
    products: list[Product] = Field(default_factory=list)


class TechnologiesFile(BaseModel):
    """Root of ``technologies.yaml``."""

    technologies: list[Technology]


class TechnologiesError(Exception):
    """Raised when ``technologies.yaml`` is missing, unreadable or invalid."""


def get_technologies_path() -> Path:
    """Return the file location from ``TECHNOLOGIES_FILE`` or the default."""
    return Path(os.environ.get("TECHNOLOGIES_FILE", DEFAULT_TECHNOLOGIES_FILE))


def load_technologies(path: Path | None = None) -> list[Technology]:
    """Load and validate the technologies file.

    Parameters:
        path: File to read. Defaults to :func:`get_technologies_path`.

    Returns:
        The technologies, in file order.

    Raises:
        TechnologiesError: If the file is missing, is not valid YAML, does not
            match the expected shape, or has duplicate technology names.
    """
    file_path = path or get_technologies_path()
    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        parsed = TechnologiesFile.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise TechnologiesError(f"Invalid technologies file {file_path}: {exc}") from exc

    names = [t.name.lower() for t in parsed.technologies]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise TechnologiesError(f"Duplicate technology names: {sorted(duplicates)}")
    return parsed.technologies
