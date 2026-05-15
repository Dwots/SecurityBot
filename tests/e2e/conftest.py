"""Shared fixtures for e2e pipeline tests (T-021)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Тестовый repo-root, чтобы pytest-collector нашёл src/sunsec по PYTHONPATH=src
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
