"""CSV upload and malware inference endpoint."""

import io
from typing import Any, Dict, Optional

import pandas as pd
from fastapi import APIRouter, File, Form, HTTPException, UploadFile

import logic.check_pandas as ai_model
from app.core.config import MODEL_PATH

router = APIRouter(tags=["upload"])


def _parse_feature_columns(raw: Optional[str]) -> Optional[list]:
    if raw is None or not str(raw).strip() or str(raw).strip().lower() == "string":
        return None
    return [c.strip() for c in str(raw).split(",") if c.strip()]


@router.post("/upload-csv")
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
