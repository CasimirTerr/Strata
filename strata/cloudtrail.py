"""Load CloudTrail records from files or folders.

Accepts the formats you actually get from AWS:
- CloudTrail S3 delivery files: {"Records": [...]}, plain or .gz
- A JSON list of records (for example from `aws cloudtrail lookup-events` after unwrapping)
- JSON Lines, one record per line (common SIEM export)
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    raw: dict

    @property
    def name(self):
        return self.raw.get("eventName", "")

    @property
    def source(self):
        return self.raw.get("eventSource", "")

    @property
    def time(self):
        return parse_time(self.raw.get("eventTime", ""))

    @property
    def time_text(self):
        return self.time.strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def region(self):
        return self.raw.get("awsRegion", "")

    @property
    def source_ip(self):
        return self.raw.get("sourceIPAddress", "")

    @property
    def error(self):
        return self.raw.get("errorCode")

    @property
    def params(self):
        return self.raw.get("requestParameters") or {}

    @property
    def principal(self):
        """The long-lived identity behind the call: the role for assumed-role sessions."""
        ident = self.raw.get("userIdentity") or {}
        issuer = ((ident.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
        return issuer or ident.get("arn") or ident.get("principalId") or ident.get("invokedBy") or "unknown"

    @property
    def event_id(self):
        return self.raw.get("eventID", "")


def parse_time(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _read_text(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def records_from_text(text: str, path: object) -> list:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for n, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {n} is not valid JSON ({exc.msg})") from None
        return records
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "eventName" in data:
        return [data]
    raise ValueError(f"{path}: no CloudTrail records found")


def _files(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(
                f for f in p.rglob("*") if f.is_file() and f.name.endswith((".json", ".json.gz", ".jsonl", ".gz"))
            )
        elif p.exists():
            yield p
        else:
            raise ValueError(f"{p}: no such file or folder")


def load_events(paths: Iterable[str | Path]) -> list[Event]:
    """Return every record as an Event, sorted by time."""
    events = []
    for f in _files(paths):
        for rec in records_from_text(_read_text(f), f):
            if isinstance(rec, dict):
                events.append(Event(rec))
    events.sort(key=lambda e: e.time)
    return events
