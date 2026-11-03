# Changelog

All notable changes to Strata are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [1.0.0] - 2026-11-03

First public release.

### Detections
- 12 single-event rules covering the eight Bedrock attack paths published by XM Cyber: invocation logging, guardrails, agents, action groups and their Lambdas, flows, managed prompts, knowledge bases, plus LLMjacking setup.
- 3 cross-agent rules for Bedrock AgentCore based on Unit 42's "Agent God Mode" research: memory, code interpreters and container images.
- Attack chains that link one identity's detections when they are less than an hour apart.
- Mappings to MITRE ATT&CK and ATLAS for every rule.

### Tooling
- `strata scan` for CloudTrail files and folders (`.json`, `.json.gz`, `.jsonl`), with text, Markdown and JSON output and `--fail-on` for automation.
- Allowlists by identity and rule, on the command line or in a config file.
- `strata export-sigma` to use the single-event rules in any SIEM that supports Sigma.
- A scheduled AWS Lambda with SNS alerts, deployed with the Terraform module in `deploy/terraform`.
- A browser version at https://casimirterr.github.io/Strata/ that runs the same engine with no server.
- "Replay as live" on the web page: streams the logs event by event with a live feed and a moving needle on the timeline.
- "Ask about these logs": a Claude chat grounded in the scan. It uses the viewer's Claude account on claude.ai, or an Anthropic API key kept in browser memory elsewhere.
- Browser checks in CI: the JavaScript engine matches Python on 303 log sets, and replay and chat work.
