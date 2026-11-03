"""Render scan results as text, Markdown or JSON."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .rules import RULES, SEVERITIES

if TYPE_CHECKING:
    from .engine import Result

NOTE = (
    "Memory, code interpreter and image-pull checks need CloudTrail data events for "
    "bedrock-agentcore and ECR. Without them, those rules can't fire."
)


def _counts(result):
    return ", ".join(f"{result.count(s)} {s.lower()}" for s in SEVERITIES)


def _short_principal(arn):
    return arn.split("/")[-1] if arn.startswith("arn:") and "/" in arn else arn


def to_text(result: Result) -> str:
    out = [
        "Strata: Bedrock attack scan",
        "=" * 60,
        f"Events scanned: {result.events_scanned} ({result.bedrock_events} from Bedrock services)",
        f"Time range: {result.first_event or 'n/a'} to {result.last_event or 'n/a'}",
        f"Detections: {len(result.detections)} ({_counts(result)})",
        f"Likely attack chains: {len(result.chains)}",
    ]
    if result.suppressed:
        out.append(f"Hidden by your allowlist: {result.suppressed}")
    out.append("")
    for i, c in enumerate(result.chains, start=1):
        out.append(f"[CRITICAL] Attack chain {i}: {_short_principal(c.principal)}, {c.start} to {c.end}")
        out.append(f"    Identity: {c.principal}")
        for d in c.steps:
            out.append(f"    {d.time[11:19]}  {d.rule_id}  {d.title}")
        out.append("")
    if result.detections:
        out.append("All detections")
        out.append("-" * 60)
    for d in result.detections:
        tags = ", ".join(d.attack + d.atlas)
        out.append(f"{d.time}  [{d.severity}] {d.rule_id}  {d.title}")
        out.append(f"    {d.detail}")
        out.append(f"    Who: {d.principal}  From: {d.source_ip or 'n/a'}  Region: {d.region or 'n/a'}")
        if tags:
            out.append(f"    Maps to: {tags}")
        out.append("")
    if not result.detections:
        out.append("Nothing suspicious found in these logs.")
    out.append(NOTE)
    return "\n".join(out)


def to_markdown(result: Result) -> str:
    out = [
        "# Strata: Bedrock attack scan",
        "",
        f"- **Events scanned:** {result.events_scanned} ({result.bedrock_events} from Bedrock services)",
        f"- **Time range:** {result.first_event or 'n/a'} to {result.last_event or 'n/a'}",
        f"- **Detections:** {len(result.detections)} ({_counts(result)})",
        f"- **Likely attack chains:** {len(result.chains)}",
    ]
    if result.suppressed:
        out.append(f"- **Hidden by your allowlist:** {result.suppressed}")
    out.append("")
    for i, c in enumerate(result.chains, start=1):
        out += [
            f"## Attack chain {i}: `{_short_principal(c.principal)}`",
            "",
            f"{c.start} to {c.end}, identity `{c.principal}`",
            "",
            "| Time (UTC) | Rule | What happened |",
            "| --- | --- | --- |",
        ]
        for d in c.steps:
            out.append(f"| {d.time[11:19]} | {d.rule_id} | {d.detail.replace('|', '/')} |")
        out.append("")
    if result.detections:
        out += [
            "## All detections",
            "",
            "| Time (UTC) | Severity | Rule | Detection | Identity |",
            "| --- | --- | --- | --- | --- |",
        ]
        for d in result.detections:
            out.append(
                f"| {d.time[:19]} | {d.severity} | {d.rule_id} | {d.title} | `{_short_principal(d.principal)}` |"
            )
        out.append("")
    else:
        out += ["Nothing suspicious found in these logs.", ""]
    out.append(f"_{NOTE}_")
    return "\n".join(out)


def _detection_dict(d):
    return {
        "rule_id": d.rule_id,
        "title": d.title,
        "severity": d.severity,
        "time": d.time,
        "principal": d.principal,
        "event_name": d.event_name,
        "region": d.region,
        "source_ip": d.source_ip,
        "detail": d.detail,
        "resource": d.resource,
        "attempted": d.attempted,
        "event_id": d.event_id,
        "attack": d.attack,
        "atlas": d.atlas,
    }


def to_dict(result: Result) -> dict:
    return {
        "events_scanned": result.events_scanned,
        "bedrock_events": result.bedrock_events,
        "first_event": result.first_event,
        "last_event": result.last_event,
        "counts": {s.lower(): result.count(s) for s in SEVERITIES},
        "suppressed": result.suppressed,
        "detections": [_detection_dict(d) for d in result.detections],
        "chains": [
            {
                "principal": c.principal,
                "start": c.start,
                "end": c.end,
                "rule_ids": c.rule_ids,
                "event_ids": [d.event_id for d in c.steps],
            }
            for c in result.chains
        ],
    }


def to_json(result: Result) -> str:
    return json.dumps(to_dict(result), indent=2)


def rules_table() -> str:
    lines = ["ID      Severity  Detection"]
    for r in RULES.values():
        lines.append(f"{r.id}  {r.severity:<8}  {r.title}")
    return "\n".join(lines)


RENDERERS = {"text": to_text, "md": to_markdown, "json": to_json}
