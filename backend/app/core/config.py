"""Application configuration and shared paths."""

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BACKEND_DIR / "ddos_model.pth"
