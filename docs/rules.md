# The rules

Every rule states a consequence rather than a policy. "Do not interpolate
untrusted input" is advice; "an attacker who comments on any issue can make this
agent push to `main`" is a claim you can check, disagree with, and act on.

Severities below are **defaults**. The trigger moves them — see
[Severity and the trigger](#severity-and-the-trigger) at the end, which is the
part worth reading if you read only one section.

`promptfence rules <id>` prints any of these in full at the terminal.

---

## `untrusted-checkout-with-agent` — critical

A job runs on a trigger that grants secrets and a write token, checks out the
contributor's code, and runs an AI agent.

```yaml
on:
  pull_request_target:          # base repo context: secrets, writable token

jobs:
  review:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # their code
      - run: claude -p 'review the diff'                   # reads their code
```

The contributor controls the files the agent reads. Instructions can be placed
in a README, a comment, a test fixture — anywhere the agent will look — and the
job is holding the base repository's secrets while it reads them.

The classic form of this bug does not even need the agent: the checked-out code
can be executed by the build, and `zizmor` will tell you so. The agent widens it
to every file it opens.

**Fix:** split the workflow. An unprivileged job builds the contributor's code
and uploads an artefact; a privileged job consumes only the result.

---

## `agent-reads-interpolated-input` — high

A `${{ }}` expression an outsider writes is placed into an agent step.

```yaml
- uses: anthropics/claude-code-action@v1
  with:
    prompt: 'Triage this: ${{ github.event.issue.body }}'
```

The value is pasted in before the agent runs, so whatever the outsider wrote
arrives as part of the instructions. Models do not reliably distinguish the data
they were given from the instructions they were given.

Contexts treated as outsider-controlled include issue and pull request bodies
and titles, comment and review bodies, discussion text, commit messages,
`github.actor` — and `github.head_ref`, a branch name, which is free text people
routinely forget about.

**Fix:** pass the text through an environment variable and tell the agent to
treat it as data. Better, keep the privileged work in a different job.

---

## `agent-ingests-untrusted-event` — high

An agent action that reads the triggering event by design, on a trigger whose
content outsiders write.

```yaml
on:
  issue_comment:
    types: [created]

jobs:
  triage:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: 'Triage the report'        # nothing interpolated
```

**There is no expression to find here.** The workflow passes nothing and the
agent still ends up holding the text of the comment that triggered it. This is
the case that tooling greping for template injection misses completely, and it
is the most common shape in practice — because it is what the quickstart in
every agent action's README produces.

Which actions ingest the event is recorded per-product in
`src/analysis/agents.ts`. If one is wrong, that is a
[false finding](../.github/ISSUE_TEMPLATE/false_finding.yml) worth reporting.

**Fix:** gate the job on `github.event.comment.author_association` being
`OWNER`, `MEMBER` or `COLLABORATOR`, and cut permissions to the minimum.

---

## `agent-inherits-all-secrets` — high

`secrets: inherit` passes the entire repository secret store to a called
workflow that runs an agent.

Inheritance is transitive and invisible from the called workflow's own file.
Nobody reviewing that file can see what it now has access to, and adding a
secret to the repository silently widens it further.

**Fix:** pass named secrets.

---

## `agent-fetches-untrusted-content` — medium

A step retrieves outsider-written text into a job that runs an agent.

```yaml
- run: gh pr view "$PR" --comments > /tmp/context.md
- run: claude -p "$(cat /tmp/context.md)"
```

The text does not have to arrive through the event payload. Recognised commands
include `gh issue view`, `gh pr view`, `gh api` against issues or comments,
`git log` with a format string, and `curl` against the GitHub issues API.

**Fix:** treat fetched text as untrusted where it is fetched, and keep the
privileged work in a separate job.

---

## `agent-holds-write-permissions` — medium

The job running an agent has write access to a scope whose abuse is not easily
undone: `contents`, `actions`, `packages`, `id-token`, `deployments`,
`attestations`.

Raised to **high** when an injection path into the agent exists *and* the
trigger is privileged.

`contents: write` means pushing code, which on a repository that publishes from
CI means shipping it. `actions: write` means rewriting the workflows that would
have caught it. `id-token: write` means minting a credential for whatever cloud
account trusts this repository, which is frequently the largest thing in reach.

Scopes like `issues: write` and `pull-requests: write` do not fire this rule. An
agent that comments is doing its job.

**Fix:** declare `permissions` on the job, narrowly.

---

## `agent-holds-secrets` — medium

Secrets beyond `GITHUB_TOKEN` are in scope where an agent runs.

**The model provider key is excluded.** Every agent needs `ANTHROPIC_API_KEY` or
its equivalent to exist at all, so a finding that counted it would fire on every
agent workflow ever written, including the ones doing everything right. It is
reported as context; only other secrets are a finding.

An agent that can run shell commands can read its own environment, so once
outsider text reaches it, every secret in scope is one persuasive instruction
away from being printed, committed, or sent somewhere.

**Fix:** scope secrets to the steps that need them rather than to the job.

---

## `agent-on-self-hosted-runner` — medium

A hosted runner is destroyed after the job. A self-hosted one is not: anything
an agent is talked into leaving behind — a modified tool on the `PATH`, a
background process, a cached credential — is there for the next job, including
jobs from other workflows.

**Fix:** hosted runners, or ephemeral self-hosted runners in a network segment
that can reach nothing else.

---

## `agent-permissions-unset` — low

Neither the workflow nor the job declares `permissions`, so the repository
default applies.

That default is a setting this analysis cannot see. On repositories created
before February 2023, or where the setting was never changed, it is write access
to almost every scope — so an agent inheriting it has more capability than
anyone reading the workflow can tell.

**Fix:** declare `permissions` explicitly. `permissions: {}` is a valid and
useful answer; being able to see the answer in the file is most of the value.

---

## `unpinned-agent-action` — low

The agent action is referenced by a tag or branch rather than a commit.

A tag is a pointer, not a version. Whoever controls the action repository can
change what it points at, and the next run executes the new code with this job's
secrets and permissions. For an action whose job is running a model with tool
access, that is a lot of trust in a mutable reference.

**Fix:** pin to a full commit SHA, with the version in a trailing comment.
Dependabot updates SHA pins.

---

## Severity and the trigger

This is the part that makes the report worth reading.

The same construction means completely different things depending on how the
workflow is triggered:

| Trigger | Runs in | Token | Secrets |
| --- | --- | --- | --- |
| `pull_request` (fork) | base repo, restricted | read-only | **none** |
| `pull_request_target` | base repo | writable | yes |
| `issue_comment`, `issues` | base repo | writable | yes |
| `discussion`, `discussion_comment` | base repo | writable | yes |
| `pull_request_review*` | base repo | writable | yes |
| `workflow_run` | base repo | writable | yes |
| `push`, `schedule`, `workflow_dispatch` | base repo | writable | yes, but no outsider content |

`pull_request` from a fork is the odd one out, and it is the one most advice
blurs. It gets a read-only token and no secrets, so an injection there has very
little to reach.

promptfence adjusts severity accordingly:

- **privileged trigger** → one step more severe
- **privileged trigger and blast radius ≥ 50** → one step more again
- **not privileged** → one step less severe
- **agent detected only as `possible`** → one step less severe

The bundled fixtures include the same interpolation on both `issue_comment`
(critical) and `pull_request` (medium), so you can see the difference before
trusting it.

A trigger printed with a `*` in the terminal report is in the privileged group.

## Suppressing a rule

`promptfence.config.json`:

```json
{
  "// warnOnly": "job is gated on author_association; see SEC-118",
  "warnOnly": ["agent-ingests-untrusted-event"],
  "disable": [],
  "exclude": ["playground.yml"]
}
```

`warnOnly` still reports the finding and stops it failing the gate — the honest
option. `disable` removes it entirely. Unknown rule ids produce a warning rather
than being silently accepted, because a typo in `disable` suppresses nothing and
reads exactly like a rule that never fires.
