"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(
        self, *, user_id: str, text: str, request_id: str | None = None
    ) -> str:
        """Start an audit record and return its correlation ID."""
        correlation_id = request_id or str(uuid4())
        self._open[correlation_id] = {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": text,
            "timestamp": utc_now_iso(),
            "started_at": perf_counter(),
        }
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete an interaction record with its decision and latency."""
        correlation_id = request_id or user_id
        started = self._open.pop(correlation_id, None)

        if started is None and request_id is None:
            # Support sequential calls that omit request_id, using the latest
            # unfinished interaction for this user.
            correlation_id = next(
                (
                    key
                    for key, item in reversed(self._open.items())
                    if item["user_id"] == user_id
                ),
                correlation_id,
            )
            started = self._open.pop(correlation_id, None)

        latency = (
            round(perf_counter() - started["started_at"], 6)
            if started is not None
            else None
        )
        self.logs.append(
            {
                "timestamp": started["timestamp"] if started else utc_now_iso(),
                "request_id": correlation_id,
                "user_id": user_id,
                "input": started["input"] if started else None,
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "latency_seconds": latency,
            }
        )
        return correlation_id

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
