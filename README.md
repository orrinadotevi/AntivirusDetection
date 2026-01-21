# AntivirusDetection (Educational)

A small, end‑to‑end demo that classifies Windows **PE** files (`.exe`, `.dll`, `.sys`) as **safe** or **malware** using a bundled scikit‑learn model.

It includes:
-  **Python package** with robust feature extraction
-  **CLI** (`avscan`) to scan a file from the terminal
-  **FastAPI backend** (`/api/scan`) to power a UI
-  A **React + Tailwind frontend** (starter) for a professional UI

>  **Safety / scope**: this is for coursework and learning. It is **not** a real antivirus product.

---

## Project layout

```
AntivirusDetection/
  antivirus_detection/        # python package (feature extraction + model + cli)
  backend/app/main.py          # FastAPI API
  frontend/                    # React UI (Vite)
  scripts/legacy/              # original scripts kept for reference
```

---

## Quickstart (backend)

### 1) Create venv and install

```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -U pip
pip install -e .
```

### 2) Run the API

```bash
uvicorn backend.app.main:app --reload --port 8000
```

Health check:
- `GET http://localhost:8000/api/health`

Scan endpoint:
- `POST http://localhost:8000/api/scan` (multipart form field: `file`)

---

## CLI usage

```bash
avscan path/to/some.exe

# JSON output
avscan path/to/some.exe --json
```

---

## Frontend (Vite + React + Tailwind)

The UI lives in `frontend/` and talks to the backend.

```bash
cd frontend
npm install
npm run dev
```

By default the backend allows CORS from `http://localhost:5173`.

---

## Retraining (optional)

The bundled model is stored in:
- `antivirus_detection/models/classifier.pk1`
- `antivirus_detection/models/features.pkl`

If you retrain, overwrite these files and keep the **feature order** consistent.

---

## License

MIT
