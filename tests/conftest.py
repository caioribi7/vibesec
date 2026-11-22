from pathlib import Path

import pytest

from vibesec.scanners.base import ScanContext
from vibesec.stack import detect

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"


@pytest.fixture
def vulnapp() -> Path:
    return FIXTURE


@pytest.fixture
def ctx(tmp_path) -> ScanContext:
    return ScanContext(root=FIXTURE, work=tmp_path, stack=detect(FIXTURE), allow_docker=False)
