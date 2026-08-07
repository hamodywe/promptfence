# Roadmap

What is planned, what is being considered, and what has been deliberately ruled
out. The last section is the one that keeps a tool small enough to trust.

## Now — 0.1.x

Reducing false negatives, because a security gate that misses things is worse
than useless — it is reassuring.

- Agent catalogue expansion, driven by false-finding reports.
- A corpus run over public repositories that use agent actions, to measure how
  often the `possible` tier is the only thing that fires.
- Windows path handling in discovery, exercised on CI rather than reasoned about.

## Next — 0.2

- **Follow composite actions.** `uses: ./.github/actions/review` is where a
  workflow's real steps often live, and an agent hidden one level down is
  currently invisible. This is the largest known gap.
- **Follow reusable workflows** within the same repository, so `secrets: inherit`
  can be reported against what the called workflow actually does with them.
- **Model `if:` gates.** A job conditioned on
  `github.event.comment.author_association` being `OWNER`, `MEMBER` or
  `COLLABORATOR` is genuinely safer, and reporting it at full severity is the
  kind of noise that gets a tool switched off. The subtlety is that the
  condition has to gate the *right* job, and a step-level `if` on the agent step
  is not the same as a job-level one.
- **`promptfence diff`** — findings a branch introduces, rather than a
  re-listing of everything the repository already lives with.

## Considering

These need evidence that people want them. If one matters to you, say so in an
issue.

- **A `--baseline` file**, to adopt the tool on an existing repository and gate
  only on what comes next. Also a way to never look at the backlog again, which
  is why it is not in "Next".
- **GitLab CI and Azure Pipelines.** The model — source, sink, blast radius —
  transfers cleanly. The parsing and the permissions semantics do not.
- **Detecting MCP server configuration** passed to an agent action, since an
  agent's tools are part of its blast radius and currently go unmodelled.
- **A JSON-schema file for the report**, so consumers can validate rather than
  trust the CHANGELOG.

## Ruled out

- **Running the workflow, or the agent.** Dynamic analysis would answer
  questions static reading cannot, and it would mean executing untrusted CI
  definitions. Not here.
- **Calling an LLM to judge a prompt.** It would be non-deterministic, it would
  need the network, and it would make the tool's central claim — that two scans
  of the same tree produce identical reports — false. It would also be a
  prompt-injection sink in a prompt-injection scanner.
- **Becoming a general workflow linter.** `zizmor` and `actionlint` are mature
  and well maintained. promptfence deliberately reports nothing about workflows
  with no agent in them, and the test suite asserts that — including on a
  workflow with a genuine `pull_request_target` bug, which is zizmor's to find.
- **Auto-fixing workflows.** The fix for most of these findings is an
  architectural split — an unprivileged job that reads, a privileged job that
  acts — and a tool that rewrote your CI to do that unattended would be a worse
  problem than the one it solved.
- **A hosted service or dashboard.** No.

## Versioning

Pre-1.0, minor versions may change severities and add rules. The `--json` report
carries a `schemaVersion` and every breaking change to it is listed in the
[CHANGELOG](CHANGELOG.md).

1.0 ships when composite actions and reusable workflows are followed, when `if:`
gates are modelled, and when the false-negative rate on a public corpus is known
rather than guessed. Not before.
