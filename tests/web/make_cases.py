"""Write tests/web/cases.json: log sets plus the Python engine's answers, for check_web.js.

The cases mix the sample logs with randomly broken and reshuffled copies (missing fields,
denied calls, odd identities, nulls) so the JavaScript port is compared on edge cases too.
"""

import copy
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from strata.cloudtrail import Event  # noqa: E402
from strata.engine import scan  # noqa: E402
from strata.report import to_dict  # noqa: E402

ERRORS = [None, None, None, "AccessDenied", "AccessDeniedException"]
WHO = ["arn:aws:iam::1:role/A", "arn:aws:iam::1:role/B", "arn:aws:iam::1:user/c", None]
EXTRA = [
    {
        "eventTime": "2026-11-03T05:00:00Z",
        "eventSource": "bedrock.amazonaws.com",
        "eventName": "UpdateGuardrail",
        "requestParameters": {
            "guardrailIdentifier": None,
            "contentPolicyConfig": {
                "filtersConfig": [
                    {"type": "PROMPT_ATTACK", "inputStrength": "NONE", "outputStrength": "NONE"},
                    "x",
                    {"outputStrength": "NONE"},
                ]
            },
            "blockedOutputsMessaging": "see www.x.io",
        },
        "userIdentity": {"arn": "arn:aws:iam::1:role/A"},
    },
    {
        "eventTime": "2026-11-03T05:01:00Z",
        "eventSource": "bedrock-agent.amazonaws.com",
        "eventName": "UpdateDataSource",
        "requestParameters": {"knowledgeBaseId": "kb1", "dataSourceId": ""},
        "userIdentity": {"arn": "arn:aws:iam::1:role/A"},
    },
    {
        "eventTime": "2026-11-03T05:02:00Z",
        "eventSource": "bedrock.amazonaws.com",
        "eventName": "PutModelInvocationLoggingConfiguration",
        "requestParameters": {
            "loggingConfig": {
                "cloudWatchConfig": {"logGroupName": "lg"},
                "s3Config": {"bucketName": "b", "keyPrefix": "x/y/"},
            }
        },
        "userIdentity": {"arn": "arn:aws:iam::1:role/A"},
    },
    {
        "eventTime": "2026-11-03T05:03:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "requestParameters": {
            "functionName": "arn:aws:lambda:us-east-1:1:function:order-lookup:7",
            "layers": ["arn:aws:lambda:us-east-1:999:layer:evil:1"],
        },
        "userIdentity": {"arn": "arn:aws:iam::1:role/B"},
    },
    {
        "eventTime": "bad-time",
        "eventSource": "bedrock.amazonaws.com",
        "eventName": "UpdateAgent",
        "requestParameters": {"agentId": "x", "instruction": "line one\n\n   line   two " + "y" * 300},
        "userIdentity": {},
    },
    {
        "eventTime": "2026-11-03T05:05:00Z",
        "eventSource": "bedrock.amazonaws.com",
        "eventName": "UpdateAgentActionGroup",
        "requestParameters": {"agentId": "A", "actionGroupExecutor": {"customControl": "RETURN_CONTROL"}},
        "userIdentity": {"arn": "arn:aws:iam::1:role/A"},
    },
]
ALLOWS = [
    [],
    [{"principal": "deploy-pipeline", "rules": ["ST-007"]}],
    [{"principal": "arn:aws:iam::1:role/A"}],
    [{"principal": "ci-deployer", "rules": ["*"]}],
]


def mutate(rng, r):
    r = copy.deepcopy(r)
    if rng.random() < 0.3:
        e = rng.choice(ERRORS)
        if e:
            r["errorCode"] = e
        else:
            r.pop("errorCode", None)
    if rng.random() < 0.3:
        w = rng.choice(WHO)
        r["userIdentity"] = {"principalId": "AIDX"} if w is None else {"arn": w}
    if rng.random() < 0.15:
        r["requestParameters"] = None
    if rng.random() < 0.2:
        r["eventTime"] = (
            f"2026-11-0{rng.randint(1, 4)}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}Z"
        )
    return r


def main(n=300, seed=11):
    rng = random.Random(seed)
    load = lambda name: json.loads((ROOT / "examples" / name / "cloudtrail.json").read_text())["Records"]  # noqa: E731
    attack, normal = load("attack-night"), load("normal-day")
    cases = [
        {"records": attack, "lambdas": [], "allow": []},
        {"records": normal, "lambdas": [], "allow": []},
        {"records": EXTRA, "lambdas": ["order-lookup"], "allow": []},
    ]
    for _ in range(n):
        recs = [mutate(rng, rng.choice(attack + normal)) for _ in range(rng.randint(1, 40))]
        recs += rng.sample(EXTRA, rng.randint(0, 3))
        cases.append(
            {
                "records": recs,
                "lambdas": rng.choice([[], ["order-lookup"], ["thumbnail-resizer"]]),
                "allow": rng.choice(ALLOWS),
            }
        )
    for c in cases:
        events = sorted((Event(r) for r in c["records"] if isinstance(r, dict)), key=lambda e: e.time)
        c["expected"] = to_dict(scan(events, agent_lambdas=c["lambdas"], allow=c["allow"]))
    out = Path(__file__).with_name("cases.json")
    out.write_text(json.dumps(cases))
    print(f"wrote {len(cases)} cases to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
