# Results

Tested 2026-07-29 against the behavior announced in
[GitHub Actions holds potentially malicious workflows for approval](https://github.blog/changelog/2026-07-28-github-actions-holds-potentially-malicious-workflows-for-approval/).

## Result

In this matrix, GitHub deterministically held a workflow when its parsed
expression serialized the entire `secrets` context with `toJSON(secrets)` or
`toJson(secrets)`.

- The rule is parse-aware: the same text in a YAML comment was not held.
- The rule is pre-execution: an expression in an `if: false` step was held.
- A transfer sink is unnecessary: reading the serialized value's length was held.
- One named secret reference was not held, including network and artifact sinks.
- Artifact upload, shell download, persistence, destruction, and miner-like
  commands did not independently trigger a hold in these probes.
- A held run had `status=completed`, `conclusion=action_required`, and zero jobs.

This identifies one criterion, not GitHub's complete private rule set. Results
may also depend on repository visibility, actor trust, account signals, rollout,
and future classifier changes.

## Matrix

| Case | Probe | API conclusion | Run |
| --- | --- | --- | --- |
| 01 | Benign control | `success` | [30473387238](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473387238) |
| 02 | One named secret to invalid network sink | `success` | [30473538592](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473538592) |
| 03 | `toJSON(secrets)` to artifact | `action_required` | [30473564781](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473564781) |
| 04 | Invalid endpoint piped to shell | `success` | [30473593067](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473593067) |
| 05 | Skipped workflow persistence attempt | `success` | [30473624340](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473624340) |
| 06 | Skipped destructive repository commands | `success` | [30473656243](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473656243) |
| 07 | Skipped miner-like commands | `success` | [30473691803](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473691803) |
| 08 | Base64 `toJSON(secrets)` to invalid network sink | `action_required` | [30473709882](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473709882) |
| 09 | Local-only `toJSON(secrets)` evaluation | `action_required` | [30473803999](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473803999) |
| 10 | Fixed fake artifact | `success` | [30473833331](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473833331) |
| 11 | Direct `toJSON(secrets)` to invalid network sink | `action_required` | [30473884723](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473884723) |
| 12 | One named secret to artifact | `success` | [30473918264](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30473918264) |
| 13 | `toJSON(secrets)` in skipped step | `action_required` | [30474027541](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30474027541) |
| 14 | `toJSON(secrets)` text in YAML comment only | `success` | [30474071194](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30474071194) |
| 15 | Mixed-case `toJson(secrets)` | `action_required` | [30474104947](https://github.com/SecretQuebecBashing/malicious-workflow-hold-lab-20260729/actions/runs/30474104947) |

Held runs were deliberately left unapproved for inspection.
