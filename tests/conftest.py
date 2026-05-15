"""pytest fixtures, общие для всех тестов."""
from __future__ import annotations

import sys
from pathlib import Path

# Гарантируем, что `src/` в sys.path даже если pytest запущен напрямую.
SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
