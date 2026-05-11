"""CSV upload and malware inference endpoint."""

import io
import json
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from fastapi import APIRouter, File, Form, HTTPException, UploadFile

import logic.check_pandas as ai_model
from app.core.config import MODEL_PATH
from database.session import SessionLocal
from database.tables import Analysis, AnalysisResult, Log, User

router = APIRouter(tags=["upload"])

CSV_FEATURE_COLUMNS: Tuple[str, ...] = (
    "Highest Layer",
    "Packet Length",
    "Packets/Time",
    "Transport Layer",
)


def _parse_feature_columns(raw: Optional[str]) -> Optional[list]:
    if raw is None or not str(raw).strip() or str(raw).strip().lower() == "string":
        return None
    return [c.strip() for c in str(raw).split(",") if c.strip()]


def _require_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in CSV_FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                "CSV must include these columns: "
                f"{list(CSV_FEATURE_COLUMNS)}. Missing: {missing}"
            ),
        )
    # Drop everything else so inference only sees required features.
    return df[list(CSV_FEATURE_COLUMNS)].copy()


def _per_record_results(inference: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One entry per CSV row in order (matches `infer_malware_from_dataframe` output)."""
    probs = inference["probabilities"]
    labels = inference["labels"]
    return [
        {"row_index": i, "probability": float(probs[i]), "label": labels[i]}
        for i in range(len(probs))
    ]


def _get_or_create_system_user() -> User:
    """
    Uploads currently aren't authenticated, but `logs.user_id` is non-nullable.
    We create/reuse a single 'system' user to satisfy the FK.
    """
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "system").one_or_none()
        if user is not None:
            return user
        user = User(username="system", email="system@example.com", password="not-used")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def _persist_upload_result(
    *,
    user_id: int,
    filename: str,
    feature_columns: List[str],
    inference: Dict[str, Any],
) -> None:
    malware_rows = [
        r["row_index"] for r in _per_record_results(inference) if r["label"] == "Malware"
    ]
    malware_count = len(malware_rows)
    any_malware = malware_count > 0

    with SessionLocal() as db:
        log = Log(
            user_id=user_id,
            log_data=json.dumps(
                {
                    "event": "csv_upload",
                    "filename": filename,
                    "feature_columns": feature_columns,
                    "rows": inference.get("rows"),
                    "input_shape": inference.get("input_shape"),
                }
            ),
        )
        db.add(log)
        db.flush()  # populate log.id

        analysis = Analysis(
            log_id=log.id,
            analysis_data=json.dumps(inference),
        )
        db.add(analysis)
        db.flush()  # populate analysis.id

        db.add(
            AnalysisResult(
                analysis_id=analysis.id,
                malware_location=json.dumps(malware_rows),
                malware_quantity=malware_count,
                analysis_classification=any_malware,
            )
        )
        db.commit()


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
    threshold: float = Form(
        0.7,
        ge=0.0,
        le=1.0,
        description=(
            "Probability threshold: Malware if model output >= this value "
            "(default 0.7 = 70%)."
        ),
    ),
) -> Dict[str, Any]:
    content = await file.read()
    if not file.filename or not str(file.filename).lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a CSV file.",
        )
    raw_df = pd.read_csv(io.BytesIO(content))

    # IMPORTANT:
    # If you force only 4 columns but the model was trained on more features,
    # predictions will often collapse to low probabilities (everything "Not Malware").
    # So by default we let the model pick its expected columns (auto-detect / saved list).
    # If you want 4-column mode, pass feature_columns explicitly.
    cols = _parse_feature_columns(feature_columns)

    try:
        inference = ai_model.infer_malware_from_dataframe(
            raw_df,
            weights_path=MODEL_PATH,
            feature_columns=cols,
            threshold=float(threshold),
        )
        records = _per_record_results(inference)
        system_user = _get_or_create_system_user()
        _persist_upload_result(
            user_id=system_user.id,
            filename=file.filename,
            feature_columns=list(inference.get("feature_columns_used", cols or [])),
            inference=inference,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    preview = raw_df.head().to_dict(orient="list")
    return {
        "filename": file.filename,
        "rows": len(raw_df),
        "preview": preview,
        "feature_columns_requested": cols,
        "feature_columns_used": inference.get("feature_columns_used"),
        "threshold": float(threshold),
        "malware_identification": inference,
        "records": records,
    }
