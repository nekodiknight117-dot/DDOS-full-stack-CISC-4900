from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import selectinload

from database.session import SessionLocal
from database.tables import Log, User

router = APIRouter(prefix="/users", tags=["users"])


def _safe_json_loads(raw: Any, fallback: Any) -> Any:
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


def _serialize_user(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def _serialize_log(log: Log) -> Dict[str, Any]:
    return {
        "id": log.id,
        "user_id": log.user_id,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "log_data": _safe_json_loads(log.log_data, {}),
        "analysis_ids": [a.id for a in log.analyses],
    }


@router.get("/me")
def get_current_user() -> Dict[str, Any]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "system").one_or_none()
        if user is None:
            raise HTTPException(
                status_code=404,
                detail="No system user yet — upload a CSV first to create it.",
            )
        return _serialize_user(user)


@router.get("/{user_id}/logs")
def list_user_logs(user_id: int) -> List[Dict[str, Any]]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.id == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found.")
        logs = (
            db.query(Log)
            .options(selectinload(Log.analyses))
            .filter(Log.user_id == user_id)
            .order_by(Log.id.desc())
            .all()
        )
        return [_serialize_log(log) for log in logs]
