# promptfence

**Your CI runs an AI agent. Find out who can talk to it, and what it is holding.**

[![CI](https://github.com/hamodywe/promptfence/actions/workflows/ci.yml/badge.svg)](https://github.com/hamodywe/promptfence/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/promptfence.svg)](https://www.npmjs.com/package/promptfence)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)

---

## The problem

AI coding agents now run inside GitHub Actions. They triage issues, review pull
requests, and fix typos on request — triggered by `issue_comment`, `issues` and
`pull_request_target`.

Every one of those events carries text that **anyone with a GitHub account
wrote**. It goes into the agent's prompt. Models do not reliably separate the
data they were given from the instructions they were given, and an agent with
tools acts on whatever it decides its instructions are.

On its own that is a curiosity. What makes it an incident is the job around it.
`issue_comment` and `pull_request_target` run in the **base repository's**
context: repository secrets in the environment, a writable `GITHUB_TOKEN`, often
`id-token: write` for cloud deployment. So a sentence in a comment is a sentence
addressed to a job that can push to `main`.

This is not hypothetical. Three publicly confirmed incidents landed in six
months, and the shape is always the same — because it is the shape of the
quickstart in every agent action's README.

`zizmor` and `actionlint` find classic template injection: `${{ }}` interpolated
into a `run:` block. They are good at it and promptfence does not duplicate them.
Neither models the thing that matters here: **untrusted text reaching a model's
prompt, and what that model is permitted to do afterwards.**

## What it does

promptfence answers three questions per job and joins them:

| | |
| --- | --- |
| **Source** | Can an outsider get text in? Interpolated, ingested from the event payload, or fetched by a step. |
| **Sink** | Does this job run a model? Known actions, known CLIs, or a provider API key in scope. |
| **Blast radius** | What is the job holding? Write scopes, secrets, OIDC, whose code it checked out, whose machine it is on. |

None of the three is a problem alone. A finding is all three at once.

## What it looks like

```console
$ promptfence

.github/workflows/issue-triage.yml — Issue triage
  agents in: triage  ·  triggers: issue_comment*, issues*

  critical agent-ingests-untrusted-event .github/workflows/issue-triage.yml:30
    `claude-code-action` in job "triage" reads the triggering event, and this
    workflow runs on issue_comment, issues — whose content anyone can write.
    so: Someone who can write that text is giving instructions to a job that can
        push commits to this repository, mint an OIDC token for whatever cloud
        account trusts this repository and read the secrets in scope.
    fix: Gate the job on the author's association with the repository, and reduce
         its permissions to what the task actually needs.
      agent: claude-code-action — uses anthropics/claude-code-action@v1 (certain)
      trigger: issue_comment, issues — the payload is written by whoever opened
               the issue, comment or pull request
      blast radius: write: contents, id-token, issues · 3 secret(s) (68/100)
```

Note the finding above has **no `${{ }}` in it**. The workflow passes nothing;
the action reads the event payload itself. That is the most common shape in
practice, and it is invisible to anything that greps for template injection.

## The distinction that drives everything

The same interpolation means completely different things depending on the
trigger, and a tool that scores them the same is wrong twice — it cries wolf on
the harmless one and, by doing so, teaches people to scroll past the real one.

| Trigger | Token | Secrets | Verdict on the same line |
| --- | --- | --- | --- |
| `pull_request` from a fork | read-only | none | **medium** — worth fixing, nothing to reach |
| `pull_request_target` | writable | yes | **critical** |
| `issue_comment`, `issues` | writable | yes | **critical** |
| `workflow_run` | writable | yes | **critical** |

promptfence prints a `*` beside triggers in the second group. The bundled
fixtures include both cases so you can see the difference before trusting it.

## Install

```sh
npm install --save-dev promptfence
```

Or run it once:

```sh
npx promptfence
```

Requires Node 20.10 or newer. **Zero runtime dependencies** — including the YAML
parser, which is written here on purpose (see below).

## Quick start

```sh
promptfence                          # scan the current repository
promptfence check                    # fail the build on high and above
promptfence rules                    # list every rule
promptfence rules untrusted-checkout-with-agent
```

Point it at a repository root, a `.github/workflows` directory, or a single
file:

```sh
promptfence scan ./some-repo
promptfence scan .github/workflows/triage.yml
```

Try the bundled fixtures, which include two vulnerable workflows, one that is
only mildly wrong, and one that is correct:

```sh
git clone https://github.com/hamodywe/promptfence && cd promptfence
npm install
node src/cli.ts scan examples
```

## In CI

```yaml
permissions:
  contents: read

jobs:
  agent-workflows:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx promptfence check
```

Or as code-scanning alerts, so findings appear on the pull request that
introduced them:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - run: npx promptfence scan --sarif > promptfence.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: promptfence.sarif
```

Full recipes, including a pull request comment: [docs/ci.md](docs/ci.md).

## The rules

| Rule | Default | What it catches |
| --- | --- | --- |
| `untrusted-checkout-with-agent` | critical | privileged trigger + contributor's code + agent |
| `agent-reads-interpolated-input` | high | `${{ }}` an outsider writes, in an agent step |
| `agent-ingests-untrusted-event` | high | agent reads the event payload; no expression to find |
| `agent-inherits-all-secrets` | high | `secrets: inherit` into an agent workflow |
| `agent-fetches-untrusted-content` | medium | a step runs `gh pr view` into an agent job |
| `agent-holds-write-permissions` | medium | write scopes that are hard to undo |
| `agent-holds-secrets` | medium | secrets beyond the model key |
| `agent-on-self-hosted-runner` | medium | an agent on a machine that outlives the job |
| `agent-permissions-unset` | low | no `permissions` block; repository default applies |
| `unpinned-agent-action` | low | the agent action is a moving tag |

Severities shown are defaults; the trigger moves them. `promptfence rules <id>`
explains each one in full. Details: [docs/rules.md](docs/rules.md).

## Design notes

**The model key is not a finding.** Every agent needs `ANTHROPIC_API_KEY` or its
equivalent to exist at all. Reporting it as "a secret in scope" would fire on
every agent workflow ever written, including the ones doing everything right.
It is reported as context; only *other* secrets are a finding.

**Agent detection is layered, and says which layer it used.** A known action is
`certain`; a known CLI in a `run:` block is `likely`; a provider API key with no
recognised agent is `possible`. That last tier exists because this space moves
faster than any catalogue — a wrapper published last week will not be in the
list, but it will still need a key. `--strict-agents` turns it off.

**A workflow that will not parse is not a pass.** It is reported as
unanalysable, and `check` fails on it. "Found nothing" and "could not look" must
never render the same way.

**The YAML parser is hand-written.** This tool is pointed at repositories,
including forks. The parser touches hostile input first, and a full YAML
implementation is a large attack surface — the billion-laughs class of
denial-of-service exists precisely because YAML aliases expand exponentially.
This parser has no alias mechanism at all, so that class is structurally
impossible rather than mitigated. Anchors, aliases, merge keys and tags are
**refused loudly**, so a workflow using them is reported as unanalysable rather
than analysed wrongly.

**Deterministic and offline.** No network, no API keys, no telemetry. Two scans
of the same tree produce byte-identical reports.

## Limitations

Stated plainly, because a security tool that oversells itself is worse than
none.

- **It reports reachable paths, not exploits.** A finding means untrusted text
  can reach an agent that holds something worth taking. Whether a particular
  model would actually comply is not something static analysis can tell you.
- **A clean report is not a clean bill of health.** It means nothing matched.
- **Agent detection is a catalogue plus heuristics.** A wrapper this tool does
  not know, invoked without a recognisable key, is invisible. If you find one,
  [tell us](.github/ISSUE_TEMPLATE/false_finding.yml) — that is the most useful
  issue you can open.
- **Reusable workflows are not followed.** A `uses:` pointing at another
  workflow is reported for what it passes — `secrets: inherit` especially — but
  the called workflow's own steps are not analysed as part of the caller.
- **Composite actions are not followed** either. An agent hidden inside
  `./.github/actions/review` will not be seen from the workflow that calls it.
  Scan the action's own directory separately.
- **It does not model `if:` conditions.** A job gated on
  `github.event.comment.author_association == 'OWNER'` is genuinely safer, and
  promptfence will still report it. Use `promptfence.config.json` to record that
  decision with its reason.
- **Anchors and aliases are refused.** GitHub Actions permits them; this parser
  does not. Such a workflow is reported as unanalysable, never as clean.

## FAQ

**How is this different from zizmor?**
zizmor is a general GitHub Actions security linter and it is very good. It finds
template injection into `run:` blocks, unpinned actions, excessive permissions.
promptfence answers a narrower question it does not model: does outsider text
reach a *model's prompt*, and what is that model allowed to do. Run both — they
overlap on almost nothing.

**Does it call an LLM?**
No. There is no network access anywhere in the tool. Static analysis of workflow
files, and nothing else.

**Will it flag every agent workflow?**
No, and the bundled `nightly-docs.yml` fixture exists to prove it — a scheduled
trigger, narrow declared permissions, a pinned action, and only the model key in
scope produces zero findings. The test suite asserts on that, because a rule
that fires there would fire everywhere.

**Our agent job is gated on `author_association`. Is that enough?**
It is a real mitigation and promptfence does not model it yet. Record the
decision in `promptfence.config.json` with a comment explaining why — that is
what the `warnOnly` and `disable` settings are for.

**Why zero dependencies?**
Because of what the tool is for. A supply-chain security tool that arrives with
thirty transitive dependencies is making an argument against itself.

## Contributing

The most useful issue you can open is a **false finding** — a workflow flagged
that is genuinely fine, or an agent this tool failed to see. The value of a
security tool rests entirely on its verdicts being trustworthy.

See [CONTRIBUTING.md](CONTRIBUTING.md). Development is `npm install`, then
`npm test`; no build step is needed to run the CLI from source.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## Licence

[MIT](LICENSE) © hamodywe

## References

- [Securing CI/CD in an agentic world: Claude Code GitHub action case](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/) — Microsoft Security, June 2026
- [PromptPwnd: prompt injection inside GitHub Actions](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents) — Aikido
- [GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines](https://arxiv.org/html/2606.09935v1) — arXiv
- [GitHub AI agent leaks private repositories via prompt injection](https://www.csoonline.com/article/4194448/github-ai-agent-leaks-private-repositories-via-prompt-injection.html) — CSO Online
- [Keeping your GitHub Actions and workflows secure: untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) — GitHub Security Lab
- [zizmor](https://github.com/woodruffw/zizmor) — the general-purpose workflow security linter this tool deliberately does not duplicate
