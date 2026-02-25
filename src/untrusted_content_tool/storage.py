from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ContentInput, RuntimeConfig


class StorageManager:
    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.data_root = Path(config.data_root)
        self.raw_dir = self.data_root / "raw"
        self.clean_dir = self.data_root / "clean"
        self.incidents_dir = self.data_root / "incidents"

        if self.config.write_files:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            self.clean_dir.mkdir(parents=True, exist_ok=True)
            self.incidents_dir.mkdir(parents=True, exist_ok=True)

    def store_raw(self, content_id: str, payload: ContentInput) -> str | None:
        record = {
            "id": content_id,
            "timestamp": _timestamp(),
            "source": payload.source,
            "url": payload.url,
            "content_type": payload.content_type,
            "raw_content": payload.content,
            "sha256": hashlib.sha256(payload.content.encode("utf-8", errors="ignore")).hexdigest(),
        }
        return self._write(self.raw_dir / f"{content_id}.json", record)

    def store_clean(self, content_id: str, record: dict[str, Any]) -> str | None:
        return self._write(self.clean_dir / f"{content_id}.json", record)

    def store_incident(self, incident_id: str, record: dict[str, Any]) -> str | None:
        return self._write(self.incidents_dir / f"{incident_id}.json", record)

    def _write(self, path: Path, payload: dict[str, Any]) -> str | None:
        if not self.config.write_files:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(path)


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
