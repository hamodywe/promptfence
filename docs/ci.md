# Running promptfence in CI

Three recipes, in increasing order of what they ask of your team.

## 1. The gate

```yaml
name: agent workflows

on:
  pull_request:
    paths: ['.github/workflows/**']
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  promptfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx promptfence check
```

The `paths` filter is deliberate: this check is about workflow files, so
restricting it keeps the signal high and the runtime near zero.

`check` fails on findings at or above `high` by default, and on any workflow it
could not parse — "found nothing" and "could not look" must not be the same
result.

## 2. Code scanning alerts

Findings become alerts with a lifecycle: they appear on the pull request that
introduced them, can be dismissed with a stated reason, and close themselves
when fixed.

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  promptfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - run: npx promptfence scan --sarif > promptfence.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: promptfence.sarif
          category: promptfence
```

Alerts land on the workflow file and line, which is exactly the file to edit —
unusually convenient, since the subject of the analysis is committed source.

## 3. A comment on the pull request

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  promptfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - run: npx promptfence scan --markdown > report.md

      - uses: actions/github-script@v7
        with:
          script: |
            const body = require('node:fs').readFileSync('report.md', 'utf8');
            const { owner, repo } = context.repo;
            const issue_number = context.issue.number;

            const comments = await github.rest.issues.listComments({ owner, repo, issue_number });
            const mine = comments.data.find((c) =>
              c.user.type === 'Bot' && c.body.includes('Agent workflow review'));

            if (mine) {
              await github.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body });
            } else {
              await github.rest.issues.createComment({ owner, repo, issue_number, body });
            }
```

**Use `pull_request`, not `pull_request_target`.** Writing a workflow that
commits the exact class of bug this tool exists to find would be an unfortunate
way to learn the lesson. `pull_request` gets `pull-requests: write` from the
`permissions` block above and cannot see repository secrets, which is all this
job needs.

## The job summary

Costs no permissions at all:

```yaml
- run: npx promptfence scan --markdown >> "$GITHUB_STEP_SUMMARY"
```

## A pre-commit hook

The scan is a static read with no network, so it is fast enough to run on every
commit that touches a workflow:

```sh
npx promptfence check --quiet
```

## Other CI systems

```yaml
# GitLab
promptfence:
  image: node:22
  script:
    - npx promptfence check
  rules:
    - changes: ['.github/workflows/**']
```

Nothing above is GitHub-specific except the SARIF upload and the comment.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | clean |
| 1 | the gate failed |
| 2 | bad usage, or a path that could not be read |

Code 2 is worth distinguishing in a pipeline: it means the tool could not do its
job, not that your workflows are fine. Treating it as a pass is the mistake to
avoid.

## Adopting on an existing repository

A repository that already has agent workflows will light up on the first run.
Two honest ways to start, and one dishonest one.

**Start at `critical`,** then tighten:

```json
{ "failOn": "critical" }
```

**Or accept specific rules as warn-only,** with the reason recorded:

```json
{
  "// warnOnly": "triage job is gated on author_association; tracked in SEC-118",
  "warnOnly": ["agent-ingests-untrusted-event"]
}
```

The dishonest one is `disable`, which removes the finding from the report
entirely. It exists, and there are legitimate uses, but a suppressed finding
nobody can see is indistinguishable from a rule that never worked.

## Keeping output out of the way

`check` writes its report to **stdout** and its verdict to **stderr**, so this
produces a clean JSON file and still shows the reason in the log:

```sh
npx promptfence check --json > promptfence.json
```

Colour disables itself when the output is not a terminal. `NO_COLOR=1` forces it
off; `FORCE_COLOR=1` forces it on.
