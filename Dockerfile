FROM python:3.11-slim

WORKDIR /app

# Install system deps (pefile is pure python, keep slim)

COPY pyproject.toml README.md ./
COPY antivirus_detection ./antivirus_detection
COPY backend ./backend

RUN pip install -U pip && pip install .

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
