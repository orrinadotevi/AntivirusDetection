.PHONY: help install dev api test lint format ui

help:
	@echo "Targets:"
	@echo "  install  - install python deps (editable)"
	@echo "  api      - run FastAPI backend"
	@echo "  test     - run pytest"
	@echo "  lint     - ruff check"
	@echo "  format   - black format"
	@echo "  ui       - run frontend dev server (requires npm)"

install:
	python -m pip install -U pip
	pip install -e .[dev]

api:
	uvicorn backend.app.main:app --reload --port 8000

test:
	pytest -q

lint:
	ruff check .

format:
	black .

ui:
	cd frontend && npm install && npm run dev
