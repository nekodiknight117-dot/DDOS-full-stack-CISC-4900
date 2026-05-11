import io
import json
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from fastapi import APIRouter, File, Form, HTTPException, UploadFile

import logic.check_pandas as ai_model
from app.core.config import MODEL_PATH
from database.session import SessionLocal
from database.tables import Analysis, AnalysisResult, CsvSampleRow, Log, User

CSV_SAMPLE_SIZE = 10

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
    return df[list(CSV_FEATURE_COLUMNS)].copy()


def _per_record_results(inference: Dict[str, Any]) -> List[Dict[str, Any]]:
    probs = inference["probabilities"]
    labels = inference["labels"]
    return [
        {"row_index": i, "probability": float(probs[i]), "label": labels[i]}
        for i in range(len(probs))
    ]


def _get_or_create_system_user() -> User:
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "system").one_or_none()
        if user is not None:
            return user
        user = User(username="system", email="system@example.com", password="not-used")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def _persist_csv_sample(
    analysis_id: int,
    df: pd.DataFrame,
    full_csv_text: Optional[str] = None,
    n: int = CSV_SAMPLE_SIZE,
) -> None:
    head = df.head(n)
    rows: List[Dict[str, Any]] = json.loads(head.to_json(orient="records"))
    if not rows and full_csv_text is None:
        return
    with SessionLocal() as db:
        if not rows:
            db.add(
                CsvSampleRow(
                    analysis_id=analysis_id,
                    row_index=0,
                    row_data=json.dumps({}),
                    full_csv=full_csv_text,
                )
            )
        else:
            for idx, row in enumerate(rows):
                db.add(
                    CsvSampleRow(
                        analysis_id=analysis_id,
                        row_index=idx,
                        row_data=json.dumps(row),
                        full_csv=full_csv_text if idx == 0 else None,
                    )
                )
        db.commit()


def _persist_upload_result(
    *,
    user_id: int,
    filename: str,
    feature_columns: List[str],
    inference: Dict[str, Any],
) -> int:
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
        db.flush()

        analysis = Analysis(
            log_id=log.id,
            analysis_data=json.dumps(inference),
        )
        db.add(analysis)
        db.flush()

        db.add(
            AnalysisResult(
                analysis_id=analysis.id,
                malware_location=json.dumps(malware_rows),
                malware_quantity=malware_count,
                analysis_classification=any_malware,
            )
        )
        db.commit()
        return analysis.id


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
        analysis_id = _persist_upload_result(
            user_id=system_user.id,
            filename=file.filename,
            feature_columns=list(inference.get("feature_columns_used", cols or [])),
            inference=inference,
        )
        full_csv_text = content.decode("utf-8-sig", errors="replace")
        _persist_csv_sample(analysis_id, raw_df, full_csv_text=full_csv_text)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    preview = raw_df.head().to_dict(orient="list")
    return {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "rows": len(raw_df),
        "preview": preview,
        "feature_columns_requested": cols,
        "feature_columns_used": inference.get("feature_columns_used"),
        "threshold": float(threshold),
        "malware_identification": inference,
        "records": records,
    }
