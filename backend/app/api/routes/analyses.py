from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import selectinload

from database.session import SessionLocal
from database.tables import Analysis, CsvSampleRow

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _safe_json_loads(raw: Any, fallback: Any) -> Any:
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


def _serialize_sample_row(row: CsvSampleRow) -> Dict[str, Any]:
    return {
        "row_index": row.row_index,
        "row_data": _safe_json_loads(row.row_data, {}),
    }


def _full_csv_filename(analysis: Analysis) -> str:
    log = analysis.log
    if log and log.log_data:
        log_data = _safe_json_loads(log.log_data, {})
        original = log_data.get("filename")
        if isinstance(original, str) and original.strip():
            return original
    return f"analysis-{analysis.id}.csv"


def _full_csv_for(analysis: Analysis) -> Optional[str]:
    rows = sorted(analysis.csv_sample_rows, key=lambda r: r.row_index)
    for r in rows:
        if r.row_index == 0 and r.full_csv is not None:
            return r.full_csv
    for r in rows:
        if r.full_csv is not None:
            return r.full_csv
    return None


def _extract_malicious_records(analysis: Analysis) -> List[Dict[str, Any]]:
    if not analysis.analysis_results:
        return []
    raw_locations = _safe_json_loads(
        analysis.analysis_results[0].malware_location, []
    )
    if not isinstance(raw_locations, list) or not raw_locations:
        return []
    wanted: set[int] = set()
    for v in raw_locations:
        try:
            wanted.add(int(v))
        except (TypeError, ValueError):
            continue
    if not wanted:
        return []

    full_csv = _full_csv_for(analysis)
    if full_csv is None:
        return []

    reader = csv.DictReader(io.StringIO(full_csv))
    out: List[Dict[str, Any]] = []
    for idx, record in enumerate(reader):
        if idx in wanted:
            out.append(
                {
                    "row_index": idx,
                    "connection_number": idx + 1,
                    "row_data": record,
                }
            )
            if len(out) == len(wanted):
                break
    return out


def _serialize_analysis(analysis: Analysis) -> Dict[str, Any]:
    log = analysis.log
    analysis_data = _safe_json_loads(analysis.analysis_data, {})
    log_data = _safe_json_loads(log.log_data if log else None, {})

    results: List[Dict[str, Any]] = []
    for r in analysis.analysis_results:
        results.append(
            {
                "id": r.id,
                "malware_location": _safe_json_loads(r.malware_location, []),
                "malware_quantity": r.malware_quantity,
                "analysis_classification": bool(r.analysis_classification),
            }
        )

    sample = [
        _serialize_sample_row(row)
        for row in sorted(analysis.csv_sample_rows, key=lambda r: r.row_index)
    ]
    has_full_csv = any(
        row.full_csv is not None for row in analysis.csv_sample_rows
    )
    malicious_records = _extract_malicious_records(analysis)

    return {
        "id": analysis.id,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "log_id": analysis.log_id,
        "log": log_data,
        "analysis_data": analysis_data,
        "results": results,
        "sample": sample,
        "has_full_csv": has_full_csv,
        "malicious_records": malicious_records,
    }


_ANALYSIS_LOAD_OPTIONS = (
    selectinload(Analysis.log),
    selectinload(Analysis.analysis_results),
    selectinload(Analysis.csv_sample_rows),
)


@router.get("/latest")
def get_latest_analysis() -> Dict[str, Any]:
    with SessionLocal() as db:
        analysis = (
            db.query(Analysis)
            .options(*_ANALYSIS_LOAD_OPTIONS)
            .order_by(Analysis.id.desc())
            .first()
        )
        if analysis is None:
            raise HTTPException(status_code=404, detail="No analyses found.")
        return _serialize_analysis(analysis)


@router.get("/{analysis_id}")
def get_analysis(analysis_id: int) -> Dict[str, Any]:
    with SessionLocal() as db:
        analysis = (
            db.query(Analysis)
            .options(*_ANALYSIS_LOAD_OPTIONS)
            .filter(Analysis.id == analysis_id)
            .one_or_none()
        )
        if analysis is None:
            raise HTTPException(
                status_code=404, detail=f"Analysis {analysis_id} not found."
            )
        return _serialize_analysis(analysis)


@router.get("/{analysis_id}/sample")
def get_analysis_sample(analysis_id: int) -> List[Dict[str, Any]]:
    with SessionLocal() as db:
        exists = db.query(Analysis.id).filter(Analysis.id == analysis_id).one_or_none()
        if exists is None:
            raise HTTPException(
                status_code=404, detail=f"Analysis {analysis_id} not found."
            )
        rows = (
            db.query(CsvSampleRow)
            .filter(CsvSampleRow.analysis_id == analysis_id)
            .order_by(CsvSampleRow.row_index.asc())
            .all()
        )
        return [_serialize_sample_row(r) for r in rows]


@router.get("/{analysis_id}/csv", response_class=PlainTextResponse)
def get_analysis_full_csv(analysis_id: int) -> Response:
    with SessionLocal() as db:
        analysis = (
            db.query(Analysis)
            .options(selectinload(Analysis.log))
            .filter(Analysis.id == analysis_id)
            .one_or_none()
        )
        if analysis is None:
            raise HTTPException(
                status_code=404, detail=f"Analysis {analysis_id} not found."
            )
        first_row = (
            db.query(CsvSampleRow)
            .filter(
                CsvSampleRow.analysis_id == analysis_id,
                CsvSampleRow.full_csv.isnot(None),
            )
            .order_by(CsvSampleRow.row_index.asc())
            .first()
        )
        if first_row is None or first_row.full_csv is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No full CSV stored for analysis {analysis_id} "
                    "(predates the full_csv column)."
                ),
            )
        download_name = _full_csv_filename(analysis)
        return Response(
            content=first_row.full_csv,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{download_name}"',
            },
        )
