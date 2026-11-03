# Detections

Every rule Strata runs, what sets it off, and what to do when it fires.
This file is generated from `strata/rules.py` by `scripts/make_docs.py`, so it always matches the code.

| ID | Severity | Detection |
| --- | --- | --- |
| [ST-001](#st-001) | Critical | Bedrock invocation logging turned off |
| [ST-002](#st-002) | High | Bedrock invocation logs sent somewhere new |
| [ST-003](#st-003) | High | Guardrail deleted |
| [ST-004](#st-004) | Medium | Guardrail changed |
| [ST-005](#st-005) | Medium | Agent instructions or settings changed |
| [ST-006](#st-006) | High | Agent tool (action group) added or changed |
| [ST-007](#st-007) | High | Code behind an agent tool changed |
| [ST-008](#st-008) | Medium | Bedrock flow changed |
| [ST-009](#st-009) | Medium | Shared prompt template changed |
| [ST-010](#st-010) | Medium | Knowledge base or data source changed |
| [ST-011](#st-011) | Medium | Foundation model access turned on |
| [ST-012](#st-012) | Low | Invocation logging settings checked |
| [ST-013](#st-013) | High | One agent touched several agents' memory |
| [ST-014](#st-014) | High | One agent used several code interpreters |
| [ST-015](#st-015) | High | One agent pulled several container images |
| [ST-100](#st-100) | Critical | Likely attack chain |

## ST-001

**Bedrock invocation logging turned off** (Critical)

Stops recording prompts and responses, which blinds investigations. Attackers do this before abusing models.

**CloudTrail events:** `DeleteModelInvocationLoggingConfiguration` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1562.008](https://attack.mitre.org/techniques/T1562/008/)

**Can be normal when:** Rare. Someone decommissioning Bedrock in a test account.

**What to do:** Turn logging back on, then review everything this identity did in the last 24 hours. Add an SCP that denies this action to everyone but a break-glass role.

## ST-002

**Bedrock invocation logs sent somewhere new** (High)

Can redirect every prompt and response to a bucket or log group the attacker controls.

**CloudTrail events:** `PutModelInvocationLoggingConfiguration` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1562.008](https://attack.mitre.org/techniques/T1562/008/)

**Can be normal when:** A planned move to a new log bucket. The first setup in a log set is reported as LOW.

**What to do:** Check who owns the new bucket or log group. If it isn't yours, point logging back and treat every prompt since the change as exposed.

## ST-003

**Guardrail deleted** (High)

Removes the safety filters that block prompt attacks and sensitive data leaks.

**CloudTrail events:** `DeleteGuardrail` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

**Can be normal when:** Cleaning up an unused guardrail.

**What to do:** Confirm whether any app or agent used the guardrail. Recreate it from infrastructure code if so.

## ST-004

**Guardrail changed** (Medium)

Guardrail edits can lower filter strength, drop prompt-attack detection, or put a phishing link in the block message.

**CloudTrail events:** `UpdateGuardrail` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

**Can be normal when:** Normal tuning. Raised to HIGH only when the prompt-attack filter is gone, a filter is set to NONE, or the block message gains a link.

**What to do:** Compare the new version to the last approved one. Look hard at any link in the block message.

## ST-005

**Agent instructions or settings changed** (Medium)

Rewriting an agent's instructions can make it leak data or follow attacker goals on every request.

**CloudTrail events:** `UpdateAgent` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1565.001](https://attack.mitre.org/techniques/T1565/001/)

**Can be normal when:** Prompt engineers improving the agent. Compare against your source-controlled instructions.

**What to do:** Read the new instructions in the detection. Watch for steps that send data to a tool or tell the agent to hide what it's doing.

## ST-006

**Agent tool (action group) added or changed** (High)

A new or swapped action group lets the agent call attacker code with its own permissions.

**CloudTrail events:** `CreateAgentActionGroup`, `UpdateAgentActionGroup` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110)

**Can be normal when:** Shipping a new agent feature.

**What to do:** Check the Lambda named in the detection: who created it, what it calls, and where it sends data.

## ST-007

**Code behind an agent tool changed** (High)

Replacing the Lambda code or layers behind an action group runs attacker logic on every agent call.

**CloudTrail events:** `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2` from `lambda.amazonaws.com`

**Maps to:** [T1648](https://attack.mitre.org/techniques/T1648/), [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110)

**Can be normal when:** Your deploy pipeline. Allowlist its role for this rule so only other identities alert.

**What to do:** Diff the deployed code against your repo. A layer from another account is a strong sign of tampering.

## ST-008

**Bedrock flow changed** (Medium)

Flow edits can reroute inputs and outputs to attacker endpoints in a pipeline nobody watches.

**CloudTrail events:** `UpdateFlow`, `UpdateFlowAlias` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1565.001](https://attack.mitre.org/techniques/T1565/001/)

**Can be normal when:** Normal flow development.

**What to do:** Check for new nodes that call outside endpoints or change the KMS key.

## ST-009

**Shared prompt template changed** (Medium)

One edited prompt template injects instructions into every app that uses it.

**CloudTrail events:** `UpdatePrompt` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1565.001](https://attack.mitre.org/techniques/T1565/001/)

**Can be normal when:** Prompt engineers editing templates.

**What to do:** Review the template text for instructions that don't belong, then check which apps use it.

## ST-010

**Knowledge base or data source changed** (Medium)

Pointing a knowledge base at new data can poison answers or expose connector credentials.

**CloudTrail events:** `UpdateKnowledgeBase`, `CreateDataSource`, `UpdateDataSource`, `DeleteDataSource` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1565.001](https://attack.mitre.org/techniques/T1565/001/)

**Can be normal when:** Adding or reorganizing document sources.

**What to do:** Confirm the new source is one you own, and rotate connector secrets if the change wasn't planned.

## ST-011

**Foundation model access turned on** (Medium)

Turning on model access is a common first step in LLMjacking, where attackers run models on your bill.

**CloudTrail events:** `PutUseCaseForModelAccess`, `PutFoundationModelEntitlement`, `CreateFoundationModelAgreement` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1496](https://attack.mitre.org/techniques/T1496/)

**Can be normal when:** A team starting to use a new model.

**What to do:** Ask the team. If nobody asked for it, disable the access key and check billing for model usage.

## ST-012

**Invocation logging settings checked** (Low)

Attackers check whether prompts are being logged before they start using stolen access.

**CloudTrail events:** `GetModelInvocationLoggingConfiguration` from `bedrock.amazonaws.com`, `bedrock-agent.amazonaws.com`

**Maps to:** [T1526](https://attack.mitre.org/techniques/T1526/)

**Can be normal when:** Security tools and auditors. On its own it means little; it matters inside a chain.

**What to do:** No action alone. Look at what the same identity did next.

## ST-013

**One agent touched several agents' memory** (High)

Each agent should only use its own memory. Reading or writing others' memory is cross-agent theft or poisoning.

**CloudTrail events:** `GetMemory`, `RetrieveMemoryRecords`, `ListEvents`, `GetEvent`, `ListMemoryRecords`, `GetMemoryRecord`, `CreateEvent`, `BatchCreateMemoryRecords`, `DeleteMemoryRecord` from `bedrock-agentcore.amazonaws.com`

**Maps to:** [T1530](https://attack.mitre.org/techniques/T1530/), [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086)

**Can be normal when:** A shared memory store that several agents use on purpose.

**What to do:** Scope the agent role's memory permissions to its own memory ARN. Check the other memory for records written by this agent.

## ST-014

**One agent used several code interpreters** (High)

Interpreters run with their own roles, so using another agent's interpreter is a privilege escalation path.

**CloudTrail events:** `InvokeCodeInterpreter`, `StartCodeInterpreterSession` from `bedrock-agentcore.amazonaws.com`

**Maps to:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/)

**Can be normal when:** An agent designed to use more than one interpreter.

**What to do:** Compare the two interpreter roles. If the second has more access, treat that access as exposed.

## ST-015

**One agent pulled several container images** (High)

Pulling other agents' images exposes their code and the memory IDs stored inside them.

**CloudTrail events:** `BatchGetImage`, `GetDownloadUrlForLayer` from `ecr.amazonaws.com`

**Maps to:** [T1530](https://attack.mitre.org/techniques/T1530/)

**Can be normal when:** Agents built from a shared base image in a separate repository.

**What to do:** Limit the role's ECR access to its own repository, and rotate anything stored in the other image.

## ST-100

**Likely attack chain** (Critical)

One identity set off several different Bedrock detections close together.

**Can be normal when:** A big planned change by one admin. Check your change calendar.

**What to do:** Treat the identity as compromised until proven otherwise: disable its keys or sessions, then walk the chain from the first step.

