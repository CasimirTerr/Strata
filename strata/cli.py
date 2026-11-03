"""Command line: `strata scan <logs>` and `strata rules`."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .cloudtrail import load_events
from .engine import scan
from .report import RENDERERS, rules_table
from .sigma import export as export_sigma


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strata",
        description="Find attacks on AWS Bedrock and Bedrock AgentCore in CloudTrail logs.",
    )
    parser.add_argument("--version", action="version", version=f"strata {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan CloudTrail log files or folders")
    s.add_argument("paths", nargs="+", help="CloudTrail files (.json, .json.gz, .jsonl) or folders")
    s.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument(
        "--agent-lambda",
        action="append",
        default=[],
        metavar="NAME",
        help="Lambda function behind an agent action group (repeatable). "
        "Strata also finds these in the logs on its own.",
    )
    s.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="WHO[:RULES]",
        help="hide detections for a trusted identity, optionally only some rules, "
        "e.g. deploy-pipeline:ST-007 (repeatable)",
    )
    s.add_argument(
        "--config", metavar="FILE", help='JSON file with "agent_lambdas" and "allow" lists (see strata.example.json)'
    )
    s.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="exit 1 if anything at or above this severity is found (for CI or scheduled jobs)",
    )

    sub.add_parser("rules", help="list the detection rules")
    e = sub.add_parser("export-sigma", help="write the single-event rules as Sigma YAML for your SIEM")
    e.add_argument("folder", help="folder to write the .yml files to")
    return parser


def parse_allow(values: list[str]) -> list[dict]:
    entries = []
    for v in values:
        who, _, rules = v.partition(":")
        entries.append({"principal": who, "rules": [r.strip() for r in rules.split(",") if r.strip()] or ["*"]})
    return entries


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    unknown = set(cfg) - {"agent_lambdas", "allow"}
    if unknown:
        raise ValueError(f"{path}: unknown keys {', '.join(sorted(unknown))}")
    return cfg


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        print(rules_table())
        return 0
    if args.command == "export-sigma":
        for path in export_sigma(args.folder):
            print(f"wrote {path}")
        return 0
    try:
        cfg = load_config(args.config) if args.config else {}
        events = load_events(args.paths)
    except (OSError, ValueError) as exc:
        print(f"strata: error: {exc}", file=sys.stderr)
        return 2
    lambdas = list(cfg.get("agent_lambdas", [])) + args.agent_lambda
    allow = list(cfg.get("allow", [])) + parse_allow(args.allow)
    result = scan(events, agent_lambdas=lambdas, allow=allow)
    report = RENDERERS[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)
    return 1 if result.worst_at_or_above(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
