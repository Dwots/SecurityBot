"""Точка входа: `python -m sunsec` — поднимает uvicorn-сервер на FastAPI app."""
from __future__ import annotations


def main() -> None:
    from sunsec.app import create_app  # импорт внутри — чтобы `import sunsec` не тянул FastAPI

    settings_host = "0.0.0.0"
    settings_port = 8000

    try:
        from sunsec.config import get_settings

        s = get_settings()
        settings_host = s.host
        settings_port = s.port
    except Exception:
        # Конфиг сломан / переменные не заданы — стартуем с дефолтами,
        # но это нештатно: логгер ещё не сконфигурён, поэтому print.
        print("WARN: settings load failed, falling back to 0.0.0.0:8000")  # noqa: T201

    try:
        import uvicorn  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "uvicorn не установлен. Запустите `pip install -r requirements.txt`."
        ) from exc

    app = create_app()
    uvicorn.run(app, host=settings_host, port=settings_port, log_config=None)


if __name__ == "__main__":
    main()
