# SunSecurityBot — Makefile (T-006). Все цели описаны в README.md.
.PHONY: help install dev run test lint format typecheck clean

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= $(PYTHON) -m ruff
MYPY ?= $(PYTHON) -m mypy
SRC := src/sunsec
TESTS := tests

help:
	@echo "Доступные цели:"
	@echo "  make install   — установка runtime-зависимостей"
	@echo "  make dev       — установка runtime + dev-зависимостей"
	@echo "  make run       — запуск FastAPI сервиса (uvicorn) на HOST:PORT из .env"
	@echo "  make test      — pytest"
	@echo "  make lint      — ruff lint"
	@echo "  make format    — ruff format"
	@echo "  make typecheck — mypy"
	@echo "  make clean     — удалить кэш / __pycache__"

install:
	$(PIP) install -r requirements.txt

dev:
	$(PIP) install -r requirements-dev.txt

run:
	$(PYTHON) -m sunsec

test:
	PYTHONPATH=src $(PYTEST) $(TESTS)

lint:
	$(RUFF) check $(SRC) $(TESTS)

format:
	$(RUFF) format $(SRC) $(TESTS)

typecheck:
	$(MYPY) $(SRC)

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '.pytest_cache' -prune -exec rm -rf {} +
	find . -type d -name '.mypy_cache' -prune -exec rm -rf {} +
	find . -type d -name '.ruff_cache' -prune -exec rm -rf {} +
