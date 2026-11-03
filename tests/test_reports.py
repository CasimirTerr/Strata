"""Text, Markdown and JSON reports, and the CLI options around them."""

import json
from pathlib import Path

from strata.cli import main
from strata.cloudtrail import load_events
from strata.engine import scan
from strata.report import rules_table, to_markdown, to_text

ROOT = Path(__file__).resolve().parent.parent
ATTACK = ROOT / "examples" / "attack-night"


def attack_result(**kw):
    return scan(load_events([ATTACK]), **kw)


def test_text_report_lists_chains_before_detections():
    text = to_text(attack_result())
    assert text.index("Attack chain 1: ci-deployer") < text.index("All detections")
    assert "Maps to: T1562.008" in text
    assert "data events" in text  # reminder about AgentCore and ECR data events


def test_markdown_report_has_chain_tables():
    md = to_markdown(attack_result(allow=[{"principal": "deploy-pipeline", "rules": ["ST-007"]}]))
    assert md.startswith("# Strata: Bedrock attack scan")
    assert "## Attack chain 2: `AmazonBedrockAgentCoreSDKRuntime-us-east-1-faq_agent`" in md
    assert "| Time (UTC) | Severity | Rule | Detection | Identity |" in md
    assert "**Hidden by your allowlist:** 1" in md


def test_empty_logs_report_cleanly(tmp_path):
    (tmp_path / "empty.json").write_text('{"Records": []}')
    result = scan(load_events([tmp_path]))
    assert "Nothing suspicious found" in to_text(result)
    assert "Nothing suspicious found" in to_markdown(result)


def test_rules_table_lists_every_rule():
    table = rules_table()
    assert table.count("ST-") == 16


def test_cli_writes_report_files(tmp_path, capsys):
    out = tmp_path / "report.md"
    assert main(["scan", str(ATTACK), "-f", "md", "-o", str(out)]) == 0
    assert out.read_text().startswith("# Strata")
    assert capsys.readouterr().out == ""
    assert main(["rules"]) == 0
    assert "ST-100" in capsys.readouterr().out
    assert main(["export-sigma", str(tmp_path / "sigma")]) == 0
    assert len(list((tmp_path / "sigma").glob("*.yml"))) == 12


def test_json_report_is_stable(capsys):
    main(["scan", str(ATTACK), "-f", "json"])
    first = capsys.readouterr().out
    main(["scan", str(ATTACK), "-f", "json"])
    assert capsys.readouterr().out == first
    assert json.loads(first)["counts"] == {"critical": 1, "high": 9, "medium": 5, "low": 3}
