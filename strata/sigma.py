"""Export the single-event rules as Sigma rules for SIEMs (Splunk, Elastic, Sentinel, and others).

Sigma can't express Strata's cross-agent rules (ST-013 to ST-015) or attack chains (ST-100),
because those need state across many events, so they are left out.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from .rules import RULES, Rule

SKIP = {"ST-013", "ST-014", "ST-015", "ST-100"}
NAMESPACE = uuid.UUID("6f1b0a2e-3c4d-4e5f-8a9b-0c1d2e3f4a5b")
REFERENCES = [
    "https://thehackernews.com/2026/03/we-found-eight-attack-vectors-inside.html",
    "https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/",
    "https://github.com/CasimirTerr/Strata",
]


def _q(text):
    return "'" + str(text).replace("'", "''") + "'"


def to_sigma(rule: Rule) -> str:
    lines = [
        f"title: {_q(rule.title)}",
        f"id: {uuid.uuid5(NAMESPACE, rule.id)}",
        "status: experimental",
        f"description: {_q(rule.why + ' (Strata ' + rule.id + ')')}",
        "references:",
        *[f"    - {r}" for r in REFERENCES],
        "author: Casimir Terrence",
        "date: 2026-11-03",
        "tags:",
        *[f"    - attack.{t.lower()}" for t in rule.attack],
        "logsource:",
        "    product: aws",
        "    service: cloudtrail",
        "detection:",
        "    selection:",
        "        eventSource:",
        *[f"            - {s}" for s in rule.sources],
        "        eventName:",
        *[f"            - {e}" for e in rule.events],
        "    condition: selection",
        "falsepositives:",
        f"    - {_q(rule.false_positives)}",
        f"level: {rule.severity.lower()}",
    ]
    if not rule.attack:
        i = lines.index("tags:")
        del lines[i]
    return "\n".join(lines) + "\n"


def export(folder: str | Path) -> list[Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for rule in RULES.values():
        if rule.id in SKIP:
            continue
        slug = rule.title.lower().replace("'", "").replace("(", "").replace(")", "")
        slug = "_".join(w for w in "".join(c if c.isalnum() else " " for c in slug).split())
        path = folder / f"{rule.id.lower().replace('-', '_')}_{slug}.yml"
        path.write_text(to_sigma(rule), encoding="utf-8")
        written.append(path)
    return written
