import gzip
import json
from pathlib import Path

import pytest

from strata.cli import main
from strata.cloudtrail import Event, load_events
from strata.engine import scan

ROOT = Path(__file__).resolve().parent.parent
ROLE = "arn:aws:iam::111122223333:role/{}"


def event(name, source="bedrock.amazonaws.com", params=None, who="Admin", time="2026-11-03T02:00:00Z", error=None):
    rec = {
        "eventTime": time,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.7",
        "requestParameters": params or {},
        "eventID": f"{name}-{time}",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::111122223333:assumed-role/{who}/s",
            "sessionContext": {"sessionIssuer": {"arn": ROLE.format(who)}},
        },
    }
    if error:
        rec["errorCode"] = error
    return Event(rec)


def rule_ids(result):
    return [d.rule_id for d in result.detections]


def test_logging_turned_off_is_critical():
    r = scan([event("DeleteModelInvocationLoggingConfiguration")])
    assert rule_ids(r) == ["ST-001"]
    assert r.detections[0].severity == "CRITICAL"


def test_logging_redirect_only_high_when_destination_changes():
    first = event(
        "PutModelInvocationLoggingConfiguration",
        time="2026-11-01T00:00:00Z",
        params={"loggingConfig": {"s3Config": {"bucketName": "good-logs"}}},
    )
    same = event(
        "PutModelInvocationLoggingConfiguration",
        time="2026-11-02T00:00:00Z",
        params={"loggingConfig": {"s3Config": {"bucketName": "good-logs"}}},
    )
    moved = event(
        "PutModelInvocationLoggingConfiguration",
        time="2026-11-03T00:00:00Z",
        params={"loggingConfig": {"s3Config": {"bucketName": "evil-logs"}}},
    )
    r = scan([first, same, moved])
    assert [d.severity for d in r.detections] == ["LOW", "HIGH"]
    assert "before: s3://good-logs" in r.detections[1].detail


def test_guardrail_weakening_and_phishing_link():
    plain = scan([event("UpdateGuardrail", params={"guardrailIdentifier": "g1", "name": "x"})])
    assert plain.detections[0].severity == "MEDIUM"

    weakened = scan(
        [
            event(
                "UpdateGuardrail",
                params={
                    "guardrailIdentifier": "g1",
                    "contentPolicyConfig": {
                        "filtersConfig": [{"type": "HATE", "inputStrength": "NONE", "outputStrength": "HIGH"}]
                    },
                    "blockedInputMessaging": "Blocked. Log in at https://evil.example to continue",
                },
            )
        ]
    )
    d = weakened.detections[0]
    assert d.severity == "HIGH"
    assert "prompt-attack filter removed" in d.detail
    assert "HATE filter set to NONE" in d.detail
    assert "phishing" in d.detail


def test_hidden_fields_do_not_crash_or_false_positive():
    r = scan(
        [
            event(
                "UpdateGuardrail",
                params={"guardrailIdentifier": "g1", "blockedInputMessaging": "HIDDEN_DUE_TO_SECURITY_REASONS"},
            )
        ]
    )
    assert r.detections[0].severity == "MEDIUM"


def test_lambda_change_only_flagged_for_agent_tools():
    group = event(
        "CreateAgentActionGroup",
        time="2026-11-01T00:00:00Z",
        params={
            "agentId": "A1",
            "actionGroupName": "tool",
            "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:111122223333:function:agent-tool:3"},
        },
    )
    agent_fn = event(
        "UpdateFunctionCode20150331v2",
        source="lambda.amazonaws.com",
        params={"functionName": "agent-tool"},
        time="2026-11-04T00:00:00Z",
    )
    other_fn = event(
        "UpdateFunctionCode20150331v2",
        source="lambda.amazonaws.com",
        params={"functionName": "image-resizer"},
        time="2026-11-04T00:01:00Z",
    )
    layer = event(
        "UpdateFunctionConfiguration20150331v2",
        source="lambda.amazonaws.com",
        params={"functionName": "agent-tool", "layers": ["arn:aws:lambda:us-east-1:999:layer:x:1"]},
        time="2026-11-04T00:02:00Z",
    )
    r = scan([group, agent_fn, other_fn, layer])
    assert rule_ids(r) == ["ST-006", "ST-007", "ST-007"]
    # Functions can also be named on the command line.
    assert rule_ids(scan([other_fn], agent_lambdas=["image-resizer"])) == ["ST-007"]


def test_denied_calls_are_marked_and_one_level_lower():
    r = scan([event("DeleteGuardrail", params={"guardrailIdentifier": "g1"}, error="AccessDeniedException")])
    d = r.detections[0]
    assert d.attempted and d.severity == "MEDIUM"
    assert d.title.startswith("Attempted:")


def agentcore(name, params, who="faq_agent", time="2026-11-03T14:00:00Z", source="bedrock-agentcore.amazonaws.com"):
    return event(name, source=source, params=params, who=f"AgentCoreRuntime-{who}", time=time)


def test_cross_agent_memory_fires_once_on_second_store():
    events = [
        agentcore("RetrieveMemoryRecords", {"memoryId": "faq-mem"}, time="2026-11-03T14:00:00Z"),
        agentcore("RetrieveMemoryRecords", {"memoryId": "faq-mem"}, time="2026-11-03T14:01:00Z"),
        agentcore("ListEvents", {"memoryId": "billing-mem"}, time="2026-11-03T14:02:00Z"),
        agentcore("ListEvents", {"memoryId": "hr-mem"}, time="2026-11-03T14:03:00Z"),
    ]
    r = scan(events)
    assert rule_ids(r) == ["ST-013"]
    assert "faq-mem, billing-mem" in r.detections[0].detail


def test_image_pulls_only_count_for_agentcore_identities():
    ecr = "ecr.amazonaws.com"
    human = [
        event("BatchGetImage", source=ecr, params={"repositoryName": r}, who="Dev", time=f"2026-11-03T10:0{i}:00Z")
        for i, r in enumerate(["a", "b", "c"])
    ]
    assert scan(human).detections == []
    agent = [agentcore("InvokeCodeInterpreter", {"codeInterpreterIdentifier": "faq_ci"})] + [
        agentcore("BatchGetImage", {"repositoryName": r}, source=ecr, time=f"2026-11-03T14:1{i}:00Z")
        for i, r in enumerate(["faq", "billing"])
    ]
    assert rule_ids(scan(agent)) == ["ST-015"]


def test_chain_rules():
    # Three different rules within an hour: chain, even at low severity.
    low = [
        event("GetModelInvocationLoggingConfiguration", time="2026-11-03T01:00:00Z"),
        event("UpdatePrompt", params={"promptIdentifier": "p"}, time="2026-11-03T01:10:00Z"),
        event("UpdateFlow", params={"flowIdentifier": "f"}, time="2026-11-03T01:20:00Z"),
    ]
    assert len(scan(low).chains) == 1
    # Same rules spread out over hours: no chain.
    spread = [
        event("GetModelInvocationLoggingConfiguration", time="2026-11-03T01:00:00Z"),
        event("UpdatePrompt", params={"promptIdentifier": "p"}, time="2026-11-03T03:00:00Z"),
        event("UpdateFlow", params={"flowIdentifier": "f"}, time="2026-11-03T05:00:00Z"),
    ]
    assert scan(spread).chains == []
    # Two rules where only one is high: no chain.
    two = [
        event("UpdatePrompt", params={"promptIdentifier": "p"}, time="2026-11-03T01:00:00Z"),
        event("DeleteGuardrail", params={"guardrailIdentifier": "g"}, time="2026-11-03T01:05:00Z"),
    ]
    assert scan(two).chains == []


def test_loader_handles_gzip_list_and_jsonl(tmp_path):
    rec = event("DeleteGuardrail", params={"guardrailIdentifier": "g"}).raw
    with gzip.open(tmp_path / "a.json.gz", "wt") as fh:
        json.dump({"Records": [rec]}, fh)
    (tmp_path / "b.json").write_text(json.dumps([rec]))
    (tmp_path / "c.jsonl").write_text(json.dumps(rec) + "\n" + json.dumps(rec) + "\n")
    assert len(load_events([tmp_path])) == 4


def test_samples_end_to_end(capsys):
    assert main(["scan", str(ROOT / "examples" / "attack-night"), "-f", "json", "--fail-on", "high"]) == 1
    report = json.loads(capsys.readouterr().out)
    principals = [c["principal"].split("/")[-1] for c in report["chains"]]
    assert principals == ["ci-deployer", "AmazonBedrockAgentCoreSDKRuntime-us-east-1-faq_agent", "temp-contractor"]

    assert main(["scan", str(ROOT / "examples" / "normal-day"), "-f", "json"]) == 0
    normal = json.loads(capsys.readouterr().out)
    assert normal["chains"] == []
    assert normal["counts"]["critical"] == 0


def test_bad_input_exits_2(tmp_path, capsys):
    (tmp_path / "bad.json").write_text("{not json\nstill not")
    assert main(["scan", str(tmp_path / "bad.json")]) == 2
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_allowlist_hides_only_listed_rules():
    group = event(
        "CreateAgentActionGroup",
        time="2026-11-01T00:00:00Z",
        who="Admin",
        params={"agentId": "A1", "actionGroupExecutor": {"lambda": "agent-tool"}},
    )
    deploy = event(
        "UpdateFunctionCode20150331v2",
        source="lambda.amazonaws.com",
        who="deploy-pipeline",
        params={"functionName": "agent-tool"},
        time="2026-11-02T00:00:00Z",
    )
    prompt = event("UpdatePrompt", who="deploy-pipeline", params={"promptIdentifier": "p"}, time="2026-11-02T00:01:00Z")
    r = scan([group, deploy, prompt], allow=[{"principal": "deploy-pipeline", "rules": ["ST-007"]}])
    assert rule_ids(r) == ["ST-006", "ST-009"]
    assert r.suppressed == 1
    full_arn = ROLE.format("deploy-pipeline")
    assert scan([deploy, prompt], agent_lambdas=["agent-tool"], allow=[{"principal": full_arn}]).detections == []


def test_cli_allow_and_config(tmp_path, capsys):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"allow": [{"principal": "PromptEngineer", "rules": ["ST-009"]}]}))
    sample = str(ROOT / "examples" / "normal-day")
    main(["scan", sample, "-f", "json", "--config", str(cfg), "--allow", "deploy-pipeline:ST-007"])
    out = json.loads(capsys.readouterr().out)
    assert out["suppressed"] == 2
    cfg.write_text(json.dumps({"alow": []}))
    assert main(["scan", sample, "--config", str(cfg)]) == 2


def test_sigma_export(tmp_path):
    from strata.sigma import export

    files = export(tmp_path)
    assert len(files) == 12
    text = (tmp_path / "st_001_bedrock_invocation_logging_turned_off.yml").read_text()
    assert "DeleteModelInvocationLoggingConfiguration" in text
    assert "level: critical" in text
    assert "attack.t1562.008" in text


def test_committed_sigma_rules_are_current(tmp_path):
    from strata.sigma import export

    for f in export(tmp_path):
        committed = ROOT / "sigma" / f.name
        assert committed.exists() and committed.read_text() == f.read_text(), (
            "Run `strata export-sigma sigma` after changing rules"
        )


def test_sigma_rules_parse_as_yaml():
    yaml = pytest.importorskip("yaml")
    for f in (ROOT / "sigma").glob("*.yml"):
        doc = yaml.safe_load(f.read_text())
        assert doc["logsource"] == {"product": "aws", "service": "cloudtrail"}
        assert doc["detection"]["selection"]["eventName"]
