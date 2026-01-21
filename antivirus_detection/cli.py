from __future__ import annotations

import json
from pathlib import Path

import typer

from .model import DEFAULT_FEATURES_PATH, DEFAULT_MODEL_PATH, MalwareClassifier

app = typer.Typer(add_completion=False, help="PE malware classification demo (educational).")


@app.command()
def scan(
    path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a PE file (.exe/.dll/.sys)."
    ),
    model: Path = typer.Option(
        DEFAULT_MODEL_PATH, "--model", help="Path to a joblib sklearn model."
    ),
    features: Path = typer.Option(
        DEFAULT_FEATURES_PATH, "--features", help="Path to a pickled feature-name list."
    ),
    json_out: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
):
    """Scan a single file."""
    clf = MalwareClassifier(model_path=model, features_path=features)
    result = clf.scan(path)

    payload = {
        "filename": result.filename,
        "label": result.label,
        "malware_probability": result.malware_probability,
        "features": result.features,
    }

    if json_out:
        typer.echo(json.dumps(payload, indent=2))
    else:
        prob_str = (
            ""
            if result.malware_probability is None
            else f" (p_malware={result.malware_probability:.3f})"
        )
        typer.echo(f"{result.filename}: {result.label}{prob_str}")


if __name__ == "__main__":
    app()
