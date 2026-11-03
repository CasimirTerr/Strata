"""Run Strata on a schedule inside AWS Lambda and send alerts to SNS.

Every run (hourly by default) the function:

1. Lists CloudTrail files delivered to S3 in the last LOOKBACK_MINUTES (default 120).
2. Scans all of them together, so attack chains that span two runs are still caught.
3. Alerts only on detections whose events arrived in the last ALERT_WINDOW_MINUTES
   (default 60, the same as the schedule), so nothing is reported twice.

The window is based on when CloudTrail delivered each file, not when the event happened.
CloudTrail can deliver an event several minutes late, and using delivery time means a late
event still falls into exactly one run.

Environment variables:
    CLOUDTRAIL_BUCKET     bucket CloudTrail writes to (required)
    CLOUDTRAIL_PREFIX     path down to the region folders, e.g. AWSLogs/111122223333/CloudTrail/ (required)
    REGIONS               comma-separated regions to read, e.g. us-east-1,us-west-2 (required)
    SNS_TOPIC_ARN         where to send alerts (required)
    MIN_SEVERITY          lowest severity that alerts: CRITICAL, HIGH, MEDIUM or LOW (default HIGH)
    LOOKBACK_MINUTES      how much history to scan for context (default 120)
    ALERT_WINDOW_MINUTES  how far back new files count as new (default 60)
    STRATA_CONFIG      optional JSON with "agent_lambdas" and "allow", same as --config
"""

from __future__ import annotations

import gzip
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

from .cloudtrail import Event, records_from_text
from .engine import Chain, Detection, Result, scan
from .rules import SEVERITIES

SNS_LIMIT = 200_000  # SNS allows 256 KB; leave room for encoding


@dataclass
class Settings:
    bucket: str
    prefix: str
    regions: list[str]
    topic_arn: str
    min_severity: str = "HIGH"
    lookback: timedelta = timedelta(minutes=120)
    alert_window: timedelta = timedelta(minutes=60)
    config: dict | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ if env is None else env)
        missing = [k for k in ("CLOUDTRAIL_BUCKET", "CLOUDTRAIL_PREFIX", "REGIONS", "SNS_TOPIC_ARN") if not env.get(k)]
        if missing:
            raise ValueError(f"missing environment variables: {', '.join(missing)}")
        severity = env.get("MIN_SEVERITY", "HIGH").upper()
        if severity not in SEVERITIES:
            raise ValueError(f"MIN_SEVERITY must be one of {', '.join(SEVERITIES)}")
        lookback = int(env.get("LOOKBACK_MINUTES", "120"))
        window = int(env.get("ALERT_WINDOW_MINUTES", "60"))
        if window > lookback:
            raise ValueError("ALERT_WINDOW_MINUTES can't be larger than LOOKBACK_MINUTES")
        prefix = env["CLOUDTRAIL_PREFIX"]
        return cls(
            bucket=env["CLOUDTRAIL_BUCKET"],
            prefix=prefix if prefix.endswith("/") else prefix + "/",
            regions=[r.strip() for r in env["REGIONS"].split(",") if r.strip()],
            topic_arn=env["SNS_TOPIC_ARN"],
            min_severity=severity,
            lookback=timedelta(minutes=lookback),
            alert_window=timedelta(minutes=window),
            config=json.loads(env["STRATA_CONFIG"]) if env.get("STRATA_CONFIG") else None,
        )


def _days(start: datetime, end: datetime) -> Iterable[date]:
    day = start.date()
    while day <= end.date():
        yield day
        day += timedelta(days=1)


def recent_objects(s3: Any, settings: Settings, now: datetime) -> list[tuple[str, datetime]]:
    """CloudTrail files delivered since now - lookback, as (key, last_modified) pairs."""
    since = now - settings.lookback
    found = []
    paginator = s3.get_paginator("list_objects_v2")
    for region in settings.regions:
        for day in _days(since, now):
            prefix = f"{settings.prefix}{region}/{day:%Y/%m/%d}/"
            for page in paginator.paginate(Bucket=settings.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if since <= obj["LastModified"] <= now:
                        found.append((obj["Key"], obj["LastModified"]))
    return found


def read_records(s3: Any, bucket: str, key: str) -> list[dict]:
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    if key.endswith(".gz"):
        body = gzip.decompress(body)
    return [r for r in records_from_text(body.decode("utf-8"), key) if isinstance(r, dict)]


def _at_or_above(severity: str, minimum: str) -> bool:
    return SEVERITIES.index(severity) <= SEVERITIES.index(minimum)


def select_alerts(result: Result, new_event_ids: set[str], minimum: str) -> tuple[list[Chain], list[Detection]]:
    """Chains with at least one new step, and new detections at or above the minimum severity."""
    chains = [c for c in result.chains if any(d.event_id in new_event_ids for d in c.steps)]
    detections = [d for d in result.detections if d.event_id in new_event_ids and _at_or_above(d.severity, minimum)]
    return chains, detections


def format_alert(chains: list[Chain], detections: list[Detection]) -> tuple[str, str]:
    parts = []
    if chains:
        parts.append(f"{len(chains)} attack chain{'s' if len(chains) != 1 else ''}")
    if detections:
        parts.append(f"{len(detections)} detection{'s' if len(detections) != 1 else ''}")
    subject = "Strata: " + ", ".join(parts)
    lines = []
    for i, c in enumerate(chains, start=1):
        lines.append(f"ATTACK CHAIN {i}: {c.principal}")
        lines.append(f"  {c.start} to {c.end}")
        for d in c.steps:
            lines.append(f"  {d.time[11:19]}  {d.rule_id}  {d.title}: {d.detail}")
        lines.append("")
    for d in detections:
        lines.append(f"[{d.severity}] {d.rule_id} {d.title}")
        lines.append(f"  {d.time}  {d.principal}  from {d.source_ip or 'n/a'} in {d.region or 'n/a'}")
        lines.append(f"  {d.detail}")
        lines.append("")
    lines.append("Rule details: https://github.com/CasimirTerr/Strata/blob/main/DETECTIONS.md")
    body = "\n".join(lines)
    if len(body) > SNS_LIMIT:
        body = body[:SNS_LIMIT] + "\n\n(cut short; run the CLI on the same logs for the full report)"
    return subject[:100], body


def run(settings: Settings, s3: Any, sns: Any, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    objects = recent_objects(s3, settings, now)
    new_since = now - settings.alert_window

    events, new_ids = [], set()
    for key, modified in objects:
        for rec in read_records(s3, settings.bucket, key):
            ev = Event(rec)
            events.append(ev)
            if modified > new_since:
                new_ids.add(ev.event_id)
    events.sort(key=lambda e: e.time)

    cfg = settings.config or {}
    result = scan(events, agent_lambdas=cfg.get("agent_lambdas", []), allow=cfg.get("allow", []))
    chains, detections = select_alerts(result, new_ids, settings.min_severity)
    if chains or detections:
        subject, body = format_alert(chains, detections)
        sns.publish(TopicArn=settings.topic_arn, Subject=subject, Message=body)

    return {
        "files": len(objects),
        "events": len(events),
        "detections": len(result.detections),
        "alerted_chains": len(chains),
        "alerted_detections": len(detections),
    }


def handler(event: dict, context: Any) -> dict:  # pragma: no cover - thin AWS wrapper
    import boto3

    settings = Settings.from_env()
    summary = run(settings, boto3.client("s3"), boto3.client("sns"))
    print(json.dumps(summary))
    return summary
