"""Test UI (T-023) — изолированный dev-модуль за флагом `ENABLE_TEST_UI`.

См. `tmp/gui_plan.md` (~325 строк) — полный план GUI. В prod НЕ включать:
даёт прямой доступ к polza.ai без HMAC-проверки GitHub-webhook.

Публичный фасад: `build_ui_router` из `sunsec.ui.router`. Использование —
`src/sunsec/app.py` за флагом `settings.enable_test_ui`.
"""
from __future__ import annotations

__all__: list[str] = []
