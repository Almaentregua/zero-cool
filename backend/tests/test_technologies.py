"""Tests for technologies.yaml loading."""

from pathlib import Path

import pytest

from zero_cool_api.technologies import TechnologiesError, load_technologies

REPO_FILE = Path(__file__).parent.parent / "technologies.yaml"


def write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "t.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_shipped_file_is_valid() -> None:
    names = [t.name for t in load_technologies(REPO_FILE)]
    assert names == ["Java", "Node.js"]


def test_new_entry_needs_no_code_change(tmp_path: Path) -> None:
    path = write(tmp_path, "technologies:\n  - name: Go\n    osv_ecosystems: [Go]\n")
    techs = load_technologies(path)
    assert techs[0].name == "Go"
    assert techs[0].products == []


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(TechnologiesError):
        load_technologies(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(TechnologiesError):
        load_technologies(write(tmp_path, "technologies: [unclosed"))


def test_wrong_shape(tmp_path: Path) -> None:
    with pytest.raises(TechnologiesError):
        load_technologies(write(tmp_path, "technologies:\n  - osv_ecosystems: [npm]\n"))


def test_duplicate_names(tmp_path: Path) -> None:
    content = "technologies:\n  - name: Go\n  - name: go\n"
    with pytest.raises(TechnologiesError, match="Duplicate"):
        load_technologies(write(tmp_path, content))
