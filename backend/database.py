import io
from pathlib import Path
from typing import Any, Dict, Optional
import json
import os
import sys
import time

import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile

import check_pandas as ai_model

BACKEND_DIR = Path(__file__).resolve().parent
MODEL_PATH = BACKEND_DIR / "ddos_model.pth"

app = FastAPI(title="DDoS CSV API", version="1.0.0")

# region agent log
def _agent_log(hypothesis_id: str, message: str, data: Dict[str, Any]) -> None:
    try:
        payload = {
            "sessionId": "3c5f41",
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
            "location": "backend/database.py:import",
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        with open(
            os.path.join(os.getcwd(), "debug-3c5f41.log"), "a", encoding="utf-8"
        ) as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass


_agent_log(
    "H1",
    "database.py imported",
    {
        "file": __file__,
        "cwd": os.getcwd(),
        "sys_path_0": sys.path[0] if sys.path else None,
        "sys_path_head": sys.path[:5],
    },
)
# endregion agent log


def _parse_feature_columns(raw: Optional[str]) -> Optional[list]:
    if raw is None or not str(raw).strip():
        return None
    return [c.strip() for c in str(raw).split(",") if c.strip()]


@app.post("/upload-csv")
async def handle_upload(
    file: UploadFile = File(...),
    feature_columns: Optional[str] = Form(
        None,
        description=(
            "Comma-separated column names to use as model inputs. "
            "If omitted, all columns are used except target, Dest IP, Source IP, "
            "Dest Port, and Source Port when present."
        ),
    ),
) -> Dict[str, Any]:
    content = await file.read()
    if not file.filename or not str(file.filename).lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a CSV file.",
        )
    df = pd.read_csv(io.BytesIO(content))
    cols = _parse_feature_columns(feature_columns)
    try:
        inference = ai_model.infer_malware_from_dataframe(
            df, weights_path=MODEL_PATH, feature_columns=cols
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    preview = df.head().to_dict(orient="list")
    return {
        "filename": file.filename,
        "rows": len(df),
        "preview": preview,
        "feature_columns_requested": cols,
        "malware_identification": inference,
    }
