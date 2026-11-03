"""Detection rules for attacks on AWS Bedrock and Bedrock AgentCore.

Sources for the attack techniques:
- XM Cyber, "We Found Eight Attack Vectors Inside AWS Bedrock" (March 2026)
- Unit 42, "Cracks in the Bedrock: Agent God Mode" (April 2026)
- Cloud Security Alliance research note on Bedrock attack vectors (March 2026)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .cloudtrail import Event

# (rule id, detail, resource, severity override or None)
Hit = tuple[str, str, str, Optional[str]]

BEDROCK_SOURCES = {"bedrock.amazonaws.com", "bedrock-agent.amazonaws.com"}
AGENTCORE_SOURCE = "bedrock-agentcore.amazonaws.com"
LAMBDA_SOURCE = "lambda.amazonaws.com"
ECR_SOURCE = "ecr.amazonaws.com"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    why: str
    attack: list = field(default_factory=list)  # MITRE ATT&CK technique IDs
    atlas: list = field(default_factory=list)  # MITRE ATLAS technique IDs
    sources: list = field(default_factory=list)  # CloudTrail eventSource values the rule reads
    events: list = field(default_factory=list)  # CloudTrail eventName values the rule reads
    false_positives: str = ""
    response: str = ""


BR = ["bedrock.amazonaws.com", "bedrock-agent.amazonaws.com"]

RULES = {
    r.id: r
    for r in [
        Rule(
            "ST-001",
            "Bedrock invocation logging turned off",
            "CRITICAL",
            "Stops recording prompts and responses, which blinds investigations. Attackers do this before abusing models.",
            attack=["T1562.008"],
            sources=BR,
            events=["DeleteModelInvocationLoggingConfiguration"],
            false_positives="Rare. Someone decommissioning Bedrock in a test account.",
            response="Turn logging back on, then review everything this identity did in the last 24 hours. "
            "Add an SCP that denies this action to everyone but a break-glass role.",
        ),
        Rule(
            "ST-002",
            "Bedrock invocation logs sent somewhere new",
            "HIGH",
            "Can redirect every prompt and response to a bucket or log group the attacker controls.",
            attack=["T1562.008"],
            sources=BR,
            events=["PutModelInvocationLoggingConfiguration"],
            false_positives="A planned move to a new log bucket. The first setup in a log set is reported as LOW.",
            response="Check who owns the new bucket or log group. If it isn't yours, point logging back and treat "
            "every prompt since the change as exposed.",
        ),
        Rule(
            "ST-003",
            "Guardrail deleted",
            "HIGH",
            "Removes the safety filters that block prompt attacks and sensitive data leaks.",
            attack=["T1562.001"],
            sources=BR,
            events=["DeleteGuardrail"],
            false_positives="Cleaning up an unused guardrail.",
            response="Confirm whether any app or agent used the guardrail. Recreate it from infrastructure code if so.",
        ),
        Rule(
            "ST-004",
            "Guardrail changed",
            "MEDIUM",
            "Guardrail edits can lower filter strength, drop prompt-attack detection, or put a phishing link in the block message.",
            attack=["T1562.001"],
            sources=BR,
            events=["UpdateGuardrail"],
            false_positives="Normal tuning. Raised to HIGH only when the prompt-attack filter is gone, a filter is set to NONE, "
            "or the block message gains a link.",
            response="Compare the new version to the last approved one. Look hard at any link in the block message.",
        ),
        Rule(
            "ST-005",
            "Agent instructions or settings changed",
            "MEDIUM",
            "Rewriting an agent's instructions can make it leak data or follow attacker goals on every request.",
            attack=["T1565.001"],
            sources=BR,
            events=["UpdateAgent"],
            false_positives="Prompt engineers improving the agent. Compare against your source-controlled instructions.",
            response="Read the new instructions in the detection. Watch for steps that send data to a tool or tell "
            "the agent to hide what it's doing.",
        ),
        Rule(
            "ST-006",
            "Agent tool (action group) added or changed",
            "HIGH",
            "A new or swapped action group lets the agent call attacker code with its own permissions.",
            atlas=["AML.T0110"],
            sources=BR,
            events=["CreateAgentActionGroup", "UpdateAgentActionGroup"],
            false_positives="Shipping a new agent feature.",
            response="Check the Lambda named in the detection: who created it, what it calls, and where it sends data.",
        ),
        Rule(
            "ST-007",
            "Code behind an agent tool changed",
            "HIGH",
            "Replacing the Lambda code or layers behind an action group runs attacker logic on every agent call.",
            attack=["T1648"],
            atlas=["AML.T0110"],
            sources=["lambda.amazonaws.com"],
            events=["UpdateFunctionCode20150331v2", "UpdateFunctionConfiguration20150331v2"],
            false_positives="Your deploy pipeline. Allowlist its role for this rule so only other identities alert.",
            response="Diff the deployed code against your repo. A layer from another account is a strong sign of tampering.",
        ),
        Rule(
            "ST-008",
            "Bedrock flow changed",
            "MEDIUM",
            "Flow edits can reroute inputs and outputs to attacker endpoints in a pipeline nobody watches.",
            attack=["T1565.001"],
            sources=BR,
            events=["UpdateFlow", "UpdateFlowAlias"],
            false_positives="Normal flow development.",
            response="Check for new nodes that call outside endpoints or change the KMS key.",
        ),
        Rule(
            "ST-009",
            "Shared prompt template changed",
            "MEDIUM",
            "One edited prompt template injects instructions into every app that uses it.",
            attack=["T1565.001"],
            sources=BR,
            events=["UpdatePrompt"],
            false_positives="Prompt engineers editing templates.",
            response="Review the template text for instructions that don't belong, then check which apps use it.",
        ),
        Rule(
            "ST-010",
            "Knowledge base or data source changed",
            "MEDIUM",
            "Pointing a knowledge base at new data can poison answers or expose connector credentials.",
            attack=["T1565.001"],
            sources=BR,
            events=["UpdateKnowledgeBase", "CreateDataSource", "UpdateDataSource", "DeleteDataSource"],
            false_positives="Adding or reorganizing document sources.",
            response="Confirm the new source is one you own, and rotate connector secrets if the change wasn't planned.",
        ),
        Rule(
            "ST-011",
            "Foundation model access turned on",
            "MEDIUM",
            "Turning on model access is a common first step in LLMjacking, where attackers run models on your bill.",
            attack=["T1496"],
            sources=BR,
            events=["PutUseCaseForModelAccess", "PutFoundationModelEntitlement", "CreateFoundationModelAgreement"],
            false_positives="A team starting to use a new model.",
            response="Ask the team. If nobody asked for it, disable the access key and check billing for model usage.",
        ),
        Rule(
            "ST-012",
            "Invocation logging settings checked",
            "LOW",
            "Attackers check whether prompts are being logged before they start using stolen access.",
            attack=["T1526"],
            sources=BR,
            events=["GetModelInvocationLoggingConfiguration"],
            false_positives="Security tools and auditors. On its own it means little; it matters inside a chain.",
            response="No action alone. Look at what the same identity did next.",
        ),
        Rule(
            "ST-013",
            "One agent touched several agents' memory",
            "HIGH",
            "Each agent should only use its own memory. Reading or writing others' memory is cross-agent theft or poisoning.",
            attack=["T1530"],
            atlas=["AML.T0086"],
            sources=[AGENTCORE_SOURCE],
            events=[
                "GetMemory",
                "RetrieveMemoryRecords",
                "ListEvents",
                "GetEvent",
                "ListMemoryRecords",
                "GetMemoryRecord",
                "CreateEvent",
                "BatchCreateMemoryRecords",
                "DeleteMemoryRecord",
            ],
            false_positives="A shared memory store that several agents use on purpose.",
            response="Scope the agent role's memory permissions to its own memory ARN. Check the other memory for "
            "records written by this agent.",
        ),
        Rule(
            "ST-014",
            "One agent used several code interpreters",
            "HIGH",
            "Interpreters run with their own roles, so using another agent's interpreter is a privilege escalation path.",
            attack=["T1078.004"],
            sources=[AGENTCORE_SOURCE],
            events=["InvokeCodeInterpreter", "StartCodeInterpreterSession"],
            false_positives="An agent designed to use more than one interpreter.",
            response="Compare the two interpreter roles. If the second has more access, treat that access as exposed.",
        ),
        Rule(
            "ST-015",
            "One agent pulled several container images",
            "HIGH",
            "Pulling other agents' images exposes their code and the memory IDs stored inside them.",
            attack=["T1530"],
            sources=["ecr.amazonaws.com"],
            events=["BatchGetImage", "GetDownloadUrlForLayer"],
            false_positives="Agents built from a shared base image in a separate repository.",
            response="Limit the role's ECR access to its own repository, and rotate anything stored in the other image.",
        ),
        Rule(
            "ST-100",
            "Likely attack chain",
            "CRITICAL",
            "One identity set off several different Bedrock detections close together.",
            false_positives="A big planned change by one admin. Check your change calendar.",
            response="Treat the identity as compromised until proven otherwise: disable its keys or sessions, then "
            "walk the chain from the first step.",
        ),
    ]
}

URL = re.compile(r"(https?://|www\.)", re.IGNORECASE)


def short(text: object, n: int = 140) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def lambda_name(value: object) -> str:
    """Turn a function name, ARN, or partial ARN into the bare function name."""
    if not value:
        return ""
    value = str(value)
    if "function:" in value:
        value = value.split("function:", 1)[1]
    return value.split(":", 1)[0]


def _val(params, key, default):
    """params[key], or the default when the key is missing, null or empty."""
    value = params.get(key)
    return default if value in (None, "") else value


def _hidden(value):
    return value in (None, "", "HIDDEN_DUE_TO_SECURITY_REASONS")


def _logging_destination(params):
    cfg = params.get("loggingConfig") or {}
    parts = []
    s3 = cfg.get("s3Config") or {}
    if s3.get("bucketName"):
        parts.append(f"s3://{s3['bucketName']}/{s3.get('keyPrefix', '')}".rstrip("/"))
    cw = cfg.get("cloudWatchConfig") or {}
    if cw.get("logGroupName"):
        parts.append(f"CloudWatch log group {cw['logGroupName']}")
    return ", ".join(parts)


def _guardrail_problems(params):
    problems = []
    content = params.get("contentPolicyConfig")
    if isinstance(content, dict):
        filters = content.get("filtersConfig") or []
        types = {f.get("type") for f in filters if isinstance(f, dict)}
        if "PROMPT_ATTACK" not in types:
            problems.append("prompt-attack filter removed")
        for f in filters:
            if not isinstance(f, dict):
                continue
            if f.get("inputStrength") == "NONE" or (
                f.get("outputStrength") == "NONE" and f.get("type") != "PROMPT_ATTACK"
            ):
                problems.append(f"{_val(f, 'type', 'a')} filter set to NONE")
    for key in ("blockedInputMessaging", "blockedOutputsMessaging"):
        msg = params.get(key)
        if isinstance(msg, str) and not _hidden(msg) and URL.search(msg):
            problems.append("link added to the block message (possible phishing)")
            break
    return problems


# Single-event rules. Each returns (rule_id, detail, resource, severity_override) or None.


def check_event(ev: Event, state: dict) -> Hit | None:
    name, src, p = ev.name, ev.source, ev.params

    if src in BEDROCK_SOURCES:
        if name == "DeleteModelInvocationLoggingConfiguration":
            return "ST-001", "Called DeleteModelInvocationLoggingConfiguration.", "model invocation logging", None
        if name == "PutModelInvocationLoggingConfiguration":
            dest = _logging_destination(p)
            prev = state.get("logging_dest")
            state["logging_dest"] = dest or prev
            if dest and prev and dest != prev:
                return "ST-002", f"Logs now go to {dest} (before: {prev}).", dest, None
            if dest and dest == prev:
                return None
            # First time we see logging set up: worth knowing, but not a redirect.
            shown = dest or "a destination hidden in the event"
            detail = f"Logs set to go to {shown}. No earlier setting in these logs to compare."
            return "ST-002", detail, dest or "model invocation logging", "LOW"
        if name == "GetModelInvocationLoggingConfiguration":
            return "ST-012", "Checked whether prompts are being logged.", "model invocation logging", None
        if name == "DeleteGuardrail":
            gid = _val(p, "guardrailIdentifier", "unknown guardrail")
            return "ST-003", f"Called DeleteGuardrail on {gid}.", gid, None
        if name == "UpdateGuardrail":
            gid = _val(p, "guardrailIdentifier", "unknown guardrail")
            problems = _guardrail_problems(p)
            if problems:
                return "ST-004", f"Guardrail {gid} changed: {', '.join(problems)}.", gid, "HIGH"
            return "ST-004", f"Guardrail {gid} settings changed.", gid, None
        if name == "UpdateAgent":
            aid = _val(p, "agentId", "unknown agent")
            instr = p.get("instruction")
            detail = f"Agent {aid} updated."
            if not _hidden(instr):
                detail += f' New instructions: "{short(instr, 220)}"'
            return "ST-005", detail, aid, None
        if name in ("CreateAgentActionGroup", "UpdateAgentActionGroup"):
            aid = _val(p, "agentId", "unknown agent")
            fn = lambda_name((p.get("actionGroupExecutor") or {}).get("lambda"))
            verb = "added to" if name.startswith("Create") else "changed on"
            detail = f"Action group '{_val(p, 'actionGroupName', 'unnamed')}' {verb} agent {aid}"
            detail += f", running Lambda {fn}." if fn else "."
            return "ST-006", detail, aid, None
        if name in ("UpdateFlow", "UpdateFlowAlias"):
            fid = _val(p, "flowIdentifier", "unknown flow")
            return "ST-008", f"Flow {fid} changed ({name}).", fid, None
        if name == "UpdatePrompt":
            pid = _val(p, "promptIdentifier", "unknown prompt")
            return "ST-009", f"Prompt template {pid} changed.", pid, None
        if name in ("UpdateKnowledgeBase", "CreateDataSource", "UpdateDataSource", "DeleteDataSource"):
            kb = _val(p, "knowledgeBaseId", "unknown knowledge base")
            ds = p.get("dataSourceId")
            target = f"{kb}/{ds}" if ds else kb
            return "ST-010", f"{name} on knowledge base {target}.", target, None
        if name in ("PutUseCaseForModelAccess", "PutFoundationModelEntitlement", "CreateFoundationModelAgreement"):
            model = _val(p, "modelId", "")
            what = {
                "PutUseCaseForModelAccess": "Submitted the use-case form that unlocks Anthropic models",
                "PutFoundationModelEntitlement": "Turned on access to " + (model or "a foundation model"),
                "CreateFoundationModelAgreement": "Accepted the model agreement for " + (model or "a foundation model"),
            }[name]
            return "ST-011", f"{what} ({name}).", model or "model access", None

    if src == LAMBDA_SOURCE:
        fn = lambda_name(p.get("functionName"))
        if fn and fn in state["agent_lambdas"]:
            if name.startswith("UpdateFunctionCode"):
                return "ST-007", f"Code replaced on {fn}, which backs an agent action group.", fn, None
            if name.startswith("UpdateFunctionConfiguration") and p.get("layers"):
                layers = ", ".join(str(x) for x in p.get("layers"))
                return (
                    "ST-007",
                    f"Layers changed on {fn}, which backs an agent action group: {short(layers, 120)}",
                    fn,
                    None,
                )
    return None


# Cross-agent rules: an AgentCore identity touching more than one agent's resources.

MEMORY_CALLS = {
    "GetMemory",
    "RetrieveMemoryRecords",
    "ListEvents",
    "GetEvent",
    "ListMemoryRecords",
    "GetMemoryRecord",
    "CreateEvent",
    "BatchCreateMemoryRecords",
    "DeleteMemoryRecord",
}
INTERPRETER_CALLS = {"InvokeCodeInterpreter", "StartCodeInterpreterSession"}
IMAGE_CALLS = {"BatchGetImage", "GetDownloadUrlForLayer"}

CROSS_AGENT = [
    ("ST-013", AGENTCORE_SOURCE, MEMORY_CALLS, "memoryId", "memory stores"),
    ("ST-014", AGENTCORE_SOURCE, INTERPRETER_CALLS, "codeInterpreterIdentifier", "code interpreters"),
    ("ST-015", ECR_SOURCE, IMAGE_CALLS, "repositoryName", "image repositories"),
]


def check_cross_agent(ev: Event, state: dict) -> Hit | None:
    """Fire once per identity and rule, at the moment it touches a second distinct resource."""
    if ev.error or ev.principal not in state["agentcore_principals"]:
        return None
    for rule_id, src, calls, key, label in CROSS_AGENT:
        if ev.source != src or ev.name not in calls:
            continue
        target = ev.params.get(key)
        if not target:
            return None
        seen = state["touched"].setdefault((rule_id, ev.principal), [])
        if target not in seen:
            seen.append(target)
        if len(seen) == 2 and (rule_id, ev.principal) not in state["fired"]:
            state["fired"].add((rule_id, ev.principal))
            return rule_id, f"Used {len(seen)} different {label}: {', '.join(seen)}.", ", ".join(seen), None
    return None
