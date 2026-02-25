"""Tests for the control mapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from comply_core.mappers.control_mapper import ControlMapper
from comply_core.mappers.framework import load_framework


@pytest.fixture
def mapper(sample_framework_path: Path) -> ControlMapper:
    framework = load_framework(sample_framework_path)
    return ControlMapper(framework)


class TestControlMapper:
    def test_get_control(self, mapper: ControlMapper) -> None:
        ctrl = mapper.get_control("A.5.17")
        assert ctrl is not None
        assert ctrl.name == "Authentication information"

    def test_get_unknown_control(self, mapper: ControlMapper) -> None:
        assert mapper.get_control("Z.99.99") is None

    def test_get_required_collectors(self, mapper: ControlMapper) -> None:
        collectors = mapper.get_required_collectors("A.5.17")
        assert len(collectors) >= 1
        assert collectors[0]["api"] == "microsoft_graph"

    def test_get_all_control_ids(self, mapper: ControlMapper) -> None:
        ids = mapper.get_all_control_ids()
        assert len(ids) >= 25
        assert "A.5.17" in ids
        assert "A.8.2" in ids

    def test_get_controls_by_category(self, mapper: ControlMapper) -> None:
        by_cat = mapper.get_controls_by_category()
        assert "Organisational" in by_cat
        assert "Technological" in by_cat

    def test_get_required_permissions(self, mapper: ControlMapper) -> None:
        perms = mapper.get_required_permissions()
        assert "Reports.Read.All" in perms
        assert "Directory.Read.All" in perms
        assert "User.Read.All" in perms
