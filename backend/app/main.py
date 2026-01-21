from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from antivirus_detection.model import MalwareClassifier

app = FastAPI(title="AntivirusDetection API", version="1.0.0")

# In dev, allow a local frontend. In production, tighten this.
allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(
    ","
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in allowed_origins if o],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

classifier = MalwareClassifier()


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    # Basic checks
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    # Store upload to temp file for scanning
    suffix = Path(file.filename).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp_path = Path(tmp.name)
        try:
            contents = await file.read()
            tmp.write(contents)
        finally:
            await file.close()

    try:
        result = classifier.scan(tmp_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    return {
        "filename": result.filename,
        "label": result.label,
        "malware_probability": result.malware_probability,
        "features": result.features,
    }
