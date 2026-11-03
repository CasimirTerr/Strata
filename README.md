# Strata

[![CI](https://github.com/CasimirTerr/Strata/actions/workflows/ci.yml/badge.svg)](https://github.com/CasimirTerr/Strata/actions/workflows/ci.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Strata reads your CloudTrail logs and finds attacks on **AWS Bedrock** and **Bedrock AgentCore**: someone hiding your prompt logs, weakening guardrails, rewriting an agent's instructions, swapping the code behind an agent's tools, or one AI agent reaching into another agent's memory.

**Try it in your browser:** [casimirterr.github.io/Strata](https://casimirterr.github.io/Strata/). Drop in a CloudTrail file or load the sample attack, hit **Replay as live** to watch the attacks unfold event by event, and ask Claude questions about what it found. Your logs never leave the page.

## Why I built this

In March 2026, XM Cyber published eight ways attackers can abuse Bedrock, and every one of them starts with an IAM permission, not a flaw in the model. A month later, Unit 42 showed that AgentCore's starter toolkit creates roles so broad that one hijacked agent can pull every other agent's container image, read their memory, and run code through their interpreters ("Agent God Mode").

When I went looking for detections, the public rules mostly watched for one thing: someone deleting the invocation logging config. The Cloud Security Alliance's write-up pointed out the same gap. The quieter moves weren't covered, like pointing the logs at a new bucket, putting a phishing link in a guardrail's block message, or swapping the Lambda behind an agent's action group. So I wrote rules for them, and for the cross-agent behavior Unit 42 described.

## What it catches

| Attack | Rules |
| --- | --- |
| Hiding or stealing prompt logs | ST-001 logging turned off, ST-002 logs sent somewhere new |
| Weakening safety filters | ST-003 guardrail deleted, ST-004 guardrail changed (raised to HIGH when the prompt-attack filter is removed, a filter is set to NONE, or the block message gets a link) |
| Hijacking an agent directly | ST-005 instructions changed, ST-006 action group added or changed |
| Hijacking an agent through its tools | ST-007 Lambda code or layers changed on a function behind an action group |
| Poisoning shared pieces | ST-008 flows, ST-009 prompt templates, ST-010 knowledge bases and data sources |
| LLMjacking (running models on your bill) | ST-011 model access turned on, ST-012 checking whether logging is on |
| Agent God Mode | ST-013 memory, ST-014 code interpreters, ST-015 container images, each when one agent touches more than one agent's resources |
| Several of the above by one identity within an hour | ST-100 likely attack chain |

Every rule maps to MITRE ATT&CK or ATLAS. [DETECTIONS.md](DETECTIONS.md) has the full write-up for each one: the exact CloudTrail events, when it's normal, and what to do when it fires.

## Quick start

```bash
git clone https://github.com/CasimirTerr/Strata.git
cd strata
pip install -e .

strata scan examples/attack-night
```

No AWS account needed for that. The sample logs are made up, but they use real CloudTrail field names and real API names. Here's the top of the output:

```text
Strata: Bedrock attack scan
============================================================
Events scanned: 53 (47 from Bedrock services)
Time range: 2026-10-29 16:02:11 UTC to 2026-11-03 21:42:02 UTC
Detections: 18 (1 critical, 9 high, 5 medium, 3 low)
Likely attack chains: 3

[CRITICAL] Attack chain 1: ci-deployer, 2026-11-03 02:10:44 UTC to 2026-11-03 02:26:31 UTC
    Identity: arn:aws:iam::111122223333:user/ci-deployer
    02:10:44  ST-012  Invocation logging settings checked
    02:12:03  ST-002  Bedrock invocation logs sent somewhere new
    02:15:37  ST-004  Guardrail changed
    02:19:12  ST-005  Agent instructions or settings changed
    02:21:40  ST-006  Agent tool (action group) added or changed
    02:24:58  ST-007  Code behind an agent tool changed
    02:26:31  ST-003  Attempted: guardrail deleted

[CRITICAL] Attack chain 2: AmazonBedrockAgentCoreSDKRuntime-us-east-1-faq_agent, ...
    14:03:15  ST-015  One agent pulled several container images
    14:06:47  ST-013  One agent touched several agents' memory
    14:09:22  ST-014  One agent used several code interpreters
```

The sample has three attacks hidden in a normal week of traffic:

1. **A stolen CI access key at 2 a.m.** It checks whether prompts are logged, redirects the logs to an outside bucket, strips the prompt-attack filter from a guardrail and adds a phishing link to its block message, tells the support agent to quietly send every customer record to a new tool, then swaps that tool's code. Its last move, deleting another guardrail, gets denied.
2. **A hijacked AgentCore agent.** The FAQ agent pulls the billing agent's container image, reads the billing agent's memory, then runs code in the billing agent's interpreter.
3. **LLMjacking with a contractor's leftover key.** It checks the logging, turns logging off, then unlocks expensive models.

Run `strata scan examples/normal-day` to compare. It shows four ordinary changes worth a glance and no chains.

## Running it on your own logs

Strata reads CloudTrail files the way AWS delivers them (`{"Records": [...]}`, plain or `.gz`), JSON lists, and JSON Lines from a SIEM export. Point it at files or whole folders:

```bash
aws s3 sync s3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/111122223333/CloudTrail/us-east-1/2026/11/03/ ./logs
strata scan ./logs
strata scan ./logs -f md -o report.md      # Markdown report
strata scan ./logs -f json                 # for other tools
```

**Turn on data events for ST-013 to ST-015.** Memory reads, code interpreter calls and ECR image pulls are data events, and CloudTrail doesn't record them unless you ask. Everything else works with the default management events.

### Cutting the noise

Your deploy pipeline will update agent Lambdas, and your prompt engineers will edit templates. Allow those identities for just those rules:

```bash
strata scan ./logs --allow deploy-pipeline:ST-007 --allow PromptEngineer:ST-009
```

Or keep it in a file (see [strata.example.json](strata.example.json)):

```json
{
  "agent_lambdas": ["order-lookup"],
  "allow": [
    {"principal": "deploy-pipeline", "rules": ["ST-007"]},
    {"principal": "PromptEngineer", "rules": ["ST-009"]}
  ]
}
```

```bash
strata scan ./logs --config strata.example.json
```

An allowlist entry can be a full ARN or just the role or user name. Allowed detections are counted in the report so they don't disappear without a trace. Keep entries narrow: an entry with no rules hides everything that identity does, so it can never show up in an attack chain either, and a stolen deploy key is exactly what you'd want to catch.

`agent_lambdas` is optional. Strata already learns which Lambdas sit behind action groups by reading `CreateAgentActionGroup` and `UpdateAgentActionGroup` events. Use it when those events are older than the logs you're scanning.

### In a pipeline or on a schedule

```bash
strata scan ./logs --fail-on high
```

The scan exits with code 1 if anything is HIGH or worse, or if it finds any attack chain. That's enough to fail a scheduled job and get an alert.

### On a schedule in your AWS account

[deploy/](deploy/) has a Terraform module that runs Strata as a Lambda every hour and sends findings to SNS (email, Slack, PagerDuty, or your SIEM). Its role can only read your CloudTrail prefix and publish to its own topic. It also sets an alarm on the function's errors, so if Strata stops running you hear about it.

```bash
python scripts/build_lambda.py
cd deploy/terraform && cp terraform.tfvars.example terraform.tfvars   # set your bucket and email
terraform init && terraform apply
```

Each run reads two hours of files so chains that cross runs are still caught, but only alerts on files that arrived since the last run, so you don't get the same alert twice. [deploy/README.md](deploy/README.md) explains the details.

### In your SIEM

```bash
strata export-sigma ./sigma
```

This writes the single-event rules (ST-001 to ST-012) as [Sigma](https://github.com/SigmaHQ/sigma) rules you can convert for Splunk, Elastic, Sentinel and others. They're also checked in under [sigma/](sigma/). The cross-agent rules and attack chains need state across many events, which Sigma can't express, so those stay in Strata.

## How it works

```
CloudTrail files ─▶ load + sort by time ─▶ single-event rules (ST-001 to ST-012)
                                        └▶ cross-agent rules (ST-013 to ST-015)
                                                   │
                         allowlist ─▶ detections ─▶ group by identity, under an hour apart ─▶ attack chains
```

A few decisions worth explaining:

- **Who did it** is the role, not the session. For assumed roles Strata uses the session issuer ARN, so one compromised role shows up as one identity even across many sessions.
- **The first logging setup is LOW.** ST-002 only goes HIGH when the destination changes from one Strata has already seen in the logs. Otherwise every new account would start with a false alarm.
- **Denied calls still count**, one severity lower, and marked "Attempted". A denied `DeleteGuardrail` in the middle of a chain is useful context.
- **Cross-agent rules only look at AgentCore identities**, meaning identities that made at least one call to `bedrock-agentcore`. They fire once per identity, at the moment it touches a second agent's resource.
- **A chain** is three or more different rules from one identity with less than an hour between steps, or two different rules that both succeeded at HIGH or CRITICAL. One busy admin making a single change doesn't count.

## The web version

[docs/index.html](docs/index.html) is a single page with the same engine ported to JavaScript. GitHub Pages serves it from the `docs` folder.

- **Timeline.** A seismograph-style chart: every detection is a spike, taller means more severe, and attack chains show up as shaded bands. Quiet stretches longer than two hours are cut out so a week of logs still fits on one screen.
- **Replay as live.** Streams the loaded events in time order into a live feed while a needle moves across the timeline. Spikes appear the moment their event arrives, and a chain's band appears once the chain is complete. A week of logs plays back in 10 to 40 seconds depending on the speed you pick. It's handy for walking someone through an incident.
- **Ask Claude.** A chat box that answers questions about the scan: what an identity did, what to lock down first, how to explain it to a manager. Claude gets the findings, the rule notes and the raw events for every identity that triggered something, and it's told to treat the log contents as evidence, not instructions.
  - On the [claude.ai copy of the page](https://claude.ai/artifact/7MYFCY9A4sFcCTqcgAX42J), it uses the viewer's own Claude account, so there's nothing to set up.
  - On GitHub Pages, you paste an Anthropic API key. The key stays in the tab's memory, goes only to `api.anthropic.com`, and disappears when you close the tab.

To keep the two engines honest, `tests/web/make_cases.py` builds 303 log sets (the samples plus hundreds of randomly mixed and broken ones) with Python's answers, and `tests/web/check_web.js` runs the page in a real browser, compares the output field by field, plays a full replay, and drives the chat against a mocked Claude in both modes. CI runs it on every push. The Python tests also fail if the rule list or sample logs in the page drift from the code. After changing rules or samples, run:

```bash
python scripts/make_samples.py   # rebuild the sample logs
python scripts/sync_web.py       # copy rules and samples into the page
python scripts/make_docs.py      # rebuild DETECTIONS.md
strata export-sigma sigma     # rebuild the Sigma rules
```

## Quality

```bash
pip install -e ".[dev]"
pytest --cov          # 32 tests, 97% coverage
ruff check . && ruff format --check . && mypy strata
python scripts/benchmark.py 100000
```

- **Tests** cover each rule's edge cases (fields CloudTrail hides, Lambda ARNs with versions, denied calls), the chain logic, every input format, the allowlist, Sigma export, all three report formats, and the Lambda against fake S3 and SNS using [moto](https://github.com/getmoto/moto). CI runs them on Python 3.9, 3.11 and 3.12 and fails under 90% coverage.
- **CI** also lints, type-checks, runs the browser checks for the web page, runs `terraform validate` on the deploy module, builds the Lambda package, and saves a report of the attack sample as a build artifact.
- **Speed:** 100,000 events in about a second on a single core, so a busy account's hourly logs scan in well under the Lambda timeout.
- **No runtime dependencies.** The package is plain Python, which keeps the Lambda zip tiny and lets the same logic run in a browser.

## Project layout

```
strata/          the package: loader, rules, engine, reports, Sigma export, Lambda handler
tests/              pytest suite, plus tests/web/ browser checks for the page
examples/           sample CloudTrail logs (attack-night, normal-day)
sigma/              generated Sigma rules
docs/index.html     the web version, served by GitHub Pages
deploy/terraform/   scheduled Lambda + SNS + least-privilege IAM
scripts/            sample, docs, web-sync, Lambda-build and benchmark scripts
DETECTIONS.md       generated reference for every rule
```

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) walks through adding a detection, and [SECURITY.md](SECURITY.md) covers reporting evasions privately.

## Limits

- Strata sees what CloudTrail sees. If an attacker uses permissions to change a Lambda's environment variables instead of its code, or edits a knowledge base's S3 bucket directly, that won't show up as a Bedrock event.
- The cross-agent rules assume one agent per role, which is how the AgentCore starter toolkit sets things up. If several agents share a role on purpose, allowlist it.
- Strata can tell you a guardrail changed, but not whether the new settings are safe for your app. ST-004 only raises the severity for changes that are almost never intentional.

## Sources

- XM Cyber via The Hacker News, [We Found Eight Attack Vectors Inside AWS Bedrock](https://thehackernews.com/2026/03/we-found-eight-attack-vectors-inside.html) (March 2026)
- Unit 42, [Cracks in the Bedrock: Agent God Mode](https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/) (April 2026)
- Cloud Security Alliance, [AWS Bedrock Attack Surface: Eight Validated Vectors](https://labs.cloudsecurityalliance.org/research/csa-research-note-aws-bedrock-attack-vectors-20260324-csa-st/) (March 2026)
- Mitigant, [AgentCore or AgentSore: Cross-Agent Privilege Escalation](https://mitigant.io/en/blog/agentcore-or-agentsore-cross-agent-privilege-escalation-in-bedrock-agentcore)

## License

MIT
