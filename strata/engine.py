"""Run the rules over CloudTrail events and link related detections into attack chains."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .rules import AGENTCORE_SOURCE, BEDROCK_SOURCES, RULES, SEVERITIES, check_cross_agent, check_event, lambda_name

if TYPE_CHECKING:
    from .cloudtrail import Event

CHAIN_WINDOW = timedelta(minutes=60)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    time: str
    principal: str
    event_name: str
    region: str
    source_ip: str
    detail: str
    resource: str
    attempted: bool = False
    event_id: str = ""
    attack: list = field(default_factory=list)
    atlas: list = field(default_factory=list)
    when: datetime = field(default=EPOCH, repr=False, compare=False)


@dataclass
class Chain:
    principal: str
    start: str
    end: str
    rule_ids: list
    steps: list


@dataclass
class Result:
    events_scanned: int
    bedrock_events: int
    first_event: str
    last_event: str
    detections: list
    chains: list
    suppressed: int = 0

    def count(self, severity: str) -> int:
        return sum(1 for d in self.detections if d.severity == severity)

    def worst_at_or_above(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        if self.chains:
            return True  # chains are always critical
        limit = SEVERITIES.index(threshold.upper())
        return any(SEVERITIES.index(d.severity) <= limit for d in self.detections)


def _one_lower(severity: str) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEVERITIES.index(severity) + 1)]


def _short_name(arn: str) -> str:
    return arn.split("/")[-1] if "/" in arn else arn


def is_allowed(detection: Detection, allow: Iterable[dict]) -> bool:
    """True if an allowlist entry covers this identity and rule.

    Entries look like {"principal": "deploy-pipeline", "rules": ["ST-007"]}. The principal can be
    a full ARN or just the role or user name. Use ["*"] to cover every rule except attack chains.
    """
    for entry in allow:
        who = entry.get("principal", "")
        if who not in (detection.principal, _short_name(detection.principal)):
            continue
        rules = entry.get("rules") or ["*"]
        if "*" in rules or detection.rule_id in rules:
            return True
    return False


def scan(events: list[Event], agent_lambdas: Iterable[str] = (), allow: Iterable[dict] = ()) -> Result:
    state: dict[str, Any] = {
        "agent_lambdas": {lambda_name(x) for x in agent_lambdas},
        "agentcore_principals": {e.principal for e in events if e.source == AGENTCORE_SOURCE},
        "touched": {},
        "fired": set(),
    }
    # Learn which Lambdas sit behind agent action groups from the logs themselves.
    for e in events:
        if (
            e.source in BEDROCK_SOURCES
            and e.name in ("CreateAgentActionGroup", "UpdateAgentActionGroup")
            and not e.error
        ):
            fn = lambda_name((e.params.get("actionGroupExecutor") or {}).get("lambda"))
            if fn:
                state["agent_lambdas"].add(fn)

    detections, suppressed = [], 0
    for ev in events:
        hit = check_event(ev, state) or check_cross_agent(ev, state)
        if not hit:
            continue
        rule_id, detail, resource, override = hit
        rule = RULES[rule_id]
        severity = override or rule.severity
        title = rule.title
        if ev.error:
            severity = _one_lower(severity)
            title = "Attempted: " + title[0].lower() + title[1:]
            detail = f"{detail} The call failed with {ev.error}."
        det = Detection(
            rule_id=rule_id,
            title=title,
            severity=severity,
            time=ev.time_text,
            principal=ev.principal,
            event_name=ev.name,
            region=ev.region,
            source_ip=ev.source_ip,
            detail=detail,
            resource=resource,
            attempted=bool(ev.error),
            event_id=ev.event_id,
            attack=list(rule.attack),
            atlas=list(rule.atlas),
            when=ev.time,
        )
        if allow and is_allowed(det, allow):
            suppressed += 1
            continue
        detections.append(det)

    return Result(
        events_scanned=len(events),
        bedrock_events=sum(1 for e in events if e.source in BEDROCK_SOURCES or e.source == AGENTCORE_SOURCE),
        first_event=events[0].time_text if events else "",
        last_event=events[-1].time_text if events else "",
        detections=detections,
        chains=find_chains(detections),
        suppressed=suppressed,
    )


def find_chains(detections: list[Detection]) -> list[Chain]:
    """Group each identity's detections that happen less than an hour apart.

    A group is a likely attack chain when it has three or more different rules, or two
    different rules that both succeeded at HIGH or CRITICAL.
    """
    by_principal: dict[str, list[Detection]] = {}
    for d in detections:
        by_principal.setdefault(d.principal, []).append(d)

    chains = []
    for principal, items in by_principal.items():
        groups, current = [], [items[0]]
        for d in items[1:]:
            if d.when - current[-1].when <= CHAIN_WINDOW:
                current.append(d)
            else:
                groups.append(current)
                current = [d]
        groups.append(current)
        for g in groups:
            rule_ids = list(dict.fromkeys(d.rule_id for d in g))
            strong = {d.rule_id for d in g if d.severity in ("CRITICAL", "HIGH") and not d.attempted}
            if len(rule_ids) >= 3 or len(strong) >= 2:
                chains.append(Chain(principal=principal, start=g[0].time, end=g[-1].time, rule_ids=rule_ids, steps=g))
    chains.sort(key=lambda c: c.start)
    return chains
