"""
Audit Logger — Barcha so'rovlarni loglash
==========================================
Huquqiy himoya uchun barcha skanerlash faoliyatini audit log faylida saqlaydi.
(TZ 6-bo'lim: "Har bir so'rov va javob audit log sifatida saqlanishi")
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


class AuditLogger:
    """
    Strukturalangan audit log yozuvchi.
    Har bir yozuv JSON formatida saqlanadi.
    """

    def __init__(self, session_id: int, target_url: str, log_dir: str = "logs/audit"):
        self.session_id = session_id
        self.target_url = target_url

        # Log papkasini yaratish
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        # Log fayl nomi: audit_<session_id>_<timestamp>.jsonl
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_path / f"audit_{session_id}_{timestamp}.jsonl"

        self._logger = logging.getLogger(f"audit.session.{session_id}")
        self._logger.info(f"Audit log boshlandi: {self.log_file}")

        # Sessiya boshlanganligi haqida yozuv
        self._write({
            "event": "SESSION_STARTED",
            "session_id": session_id,
            "target_url": target_url,
            "legal_notice": (
                "This scan is conducted for authorized security assessment purposes only. "
                "Unauthorized scanning is prohibited by law."
            )
        })

    def log_scan_start(self, scanner_name: str, target: str):
        self._write({
            "event": "SCAN_STARTED",
            "scanner": scanner_name,
            "target": target,
        })

    def log_scan_complete(self, scanner_name: str, findings_count: int, duration_ms: float):
        self._write({
            "event": "SCAN_COMPLETED",
            "scanner": scanner_name,
            "findings_count": findings_count,
            "duration_ms": round(duration_ms, 2),
        })

    def log_finding(self, finding_data: dict):
        # Xom HTTP response/payload'larni logdan chiqarib tashlash (xavfsizlik)
        safe_data = {k: v for k, v in finding_data.items()
                     if k not in ("evidence", "raw_response")}
        self._write({
            "event": "FINDING_DETECTED",
            **safe_data,
        })

    def log_error(self, scanner_name: str, error: str):
        self._write({
            "event": "SCAN_ERROR",
            "scanner": scanner_name,
            "error": error,
        })

    def log_session_end(self, total_findings: int):
        self._write({
            "event": "SESSION_COMPLETED",
            "session_id": self.session_id,
            "total_findings": total_findings,
        })

    def _write(self, data: dict):
        """JSON Lines formatida fayl yozuvi."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": self.session_id,
            **data
        }
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            self._logger.error(f"Audit log yozishda xato: {e}")

    @property
    def log_file_path(self) -> str:
        return str(self.log_file)
