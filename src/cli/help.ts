/**
 * Help text, written as prose someone can act on rather than a flag dump.
 */

import type { Command } from './args.ts';

const GENERAL = `promptfence — AI agents in your CI, and what they are holding

AI coding agents now run inside GitHub Actions, triggered by issues, comments
and pull requests. That text is written by anyone with a GitHub account, and it
arrives in the agent's prompt. When the surrounding job also holds repository
secrets and a write token, an instruction in a comment becomes an instruction to
your repository.

promptfence finds where outsider-controlled text reaches an agent, and reports
what that agent is allowed to do with it.

USAGE
  promptfence [command] [path] [options]

COMMANDS
  scan     analyse workflows and report                            (default)
  check    fail the build on findings at or above a severity       (for CI)
  rules    list the rules, or explain one in full

PATH
  A repository root, a .github/workflows directory, or a single workflow file.
  Defaults to the current directory.

OUTPUT
  --json              machine-readable report
  --markdown, --md    for a pull request comment or job summary
  --sarif             SARIF 2.1.0 for GitHub code scanning
  --verbose           also list agent jobs that produced no findings
  -q, --quiet         findings without their evidence

BEHAVIOUR
  --fail-on <level>   critical | high | medium | low | info   (check, default high)
  --strict-agents     only report steps that use a recognised agent action or
                      CLI, not steps that merely have a model API key in scope

  -h, --help          show help; pass a command for its own help
  -v, --version       print the version

EXIT CODES
  0  clean
  1  the gate failed
  2  bad usage, or a path that could not be read

EXAMPLES
  promptfence                          scan the current repository
  promptfence check --fail-on medium   a stricter gate in CI
  promptfence rules                    list every rule
  promptfence rules untrusted-checkout-with-agent

promptfence reports reachable paths, not exploits. It only looks at jobs that
run a model — general workflow security is zizmor and actionlint territory.
https://github.com/hamodywe/promptfence`;

const PER_COMMAND: Readonly<Record<Command, string>> = {
  scan: `promptfence scan [path] [options]

Analyse every workflow and report where outsider-controlled text can reach an AI
agent, together with what the surrounding job is permitted to do.

Severity depends on the trigger, and the difference is large:

  pull_request from a fork     read-only token, no secrets
  pull_request_target          base repository secrets, writable token
  issue_comment, issues        base repository secrets, writable token
  workflow_run                 base repository secrets, writable token

The same interpolation is a repository takeover under the second group and a
much smaller problem under the first. A trigger printed with a * is in the
privileged group.

  --verbose      also list agent jobs that produced no findings, with their
                 permissions — useful before changing a trigger
  -q, --quiet    findings without their evidence
  --json | --markdown | --sarif

Exits 0 unless the path could not be read.`,

  check: `promptfence check [path] [options]

The CI gate. Fails on findings at or above a severity, and on any workflow that
could not be parsed — reporting nothing and reporting nothing found must not
look the same.

  --fail-on <level>   default: high
  --json | --markdown | --sarif

Configure in promptfence.config.json:
  failOn, warnOnly, disable, exclude, includePossibleAgents

Exits 1 when the gate fails, 0 when it passes.`,

  rules: `promptfence rules [rule-id]

With no argument, lists every rule with its default severity.

With a rule id, prints that rule in full: what it claims, why it matters, and
what to change.

  promptfence rules
  promptfence rules untrusted-checkout-with-agent

  --json    the rule catalogue as data`,
};

export function helpText(command?: Command): string {
  return command ? PER_COMMAND[command] : GENERAL;
}
