# Configuration

Optional, and designed to stay that way. Every default is correct for a project
that has never heard of this file.

Create `promptfence.config.json` at the root you scan.

```json
{
  "failOn": "high",
  "warnOnly": [],
  "disable": [],
  "exclude": [],
  "includePossibleAgents": true
}
```

JSON rather than a JavaScript module: a config file that can execute code is a
strange thing to ship with a tool whose subject is untrusted code execution in
CI.

## Options

### `failOn`

`"critical" | "high" | "medium" | "low" | "info"` — default `"high"`.

Severity at or above which `promptfence check` fails.

`high` rather than `medium` on purpose. An unpinned action on a fork-triggered
workflow is worth knowing about and is not worth stopping a merge for, and a
gate that fires on everything teaches people to bypass it.

Overridden per run by `--fail-on`.

### `warnOnly`

`string[]` of rule ids — default `[]`.

Rules that are still reported but never fail the gate. `check` prints them under
a `warn-only:` prefix so they stay visible.

This is the honest suppression. Use it when a mitigation exists that promptfence
does not model — a job gated on `author_association`, for instance — and record
why:

```json
{
  "// warnOnly": "triage is gated on author_association == OWNER; tracked in SEC-118",
  "warnOnly": ["agent-ingests-untrusted-event"]
}
```

### `disable`

`string[]` of rule ids — default `[]`.

Rules removed from the report entirely.

There are legitimate uses, but prefer `warnOnly`. A finding nobody can see is
indistinguishable from a rule that never worked, which is a bad property for a
security control.

### `exclude`

`string[]` — default `[]`.

Workflow paths excluded, matched as an exact path or as a basename:

```json
{ "exclude": ["playground.yml", ".github/workflows/scratch.yml"] }
```

### `includePossibleAgents`

`boolean` — default `true`.

Whether to report a step whose only agent evidence is a model provider API key
in scope.

Leave it on. Agent actions and wrappers appear faster than any catalogue keeps
up, and the `possible` tier is what catches the one published last week. It
still needs a key.

Turn it off — or pass `--strict-agents` — when a repository has steps that hold
a model key for reasons that are not agentic, such as a test suite that records
fixtures against an API.

## Comment keys

Any key beginning with `//` is ignored, following the convention npm established
for commenting JSON. This is how a reason gets written down next to a decision,
and a suppression with its reason beside it is one the next reader can evaluate.

## Invalid values

A typo never stops a scan. Every rejected value falls back to its default and
produces a warning naming the key.

Unknown rule ids in `warnOnly` and `disable` are called out specifically:

```console
$ promptfence
warning "disable" names an unknown rule: agent-holds-secret
```

That warning matters more than it looks. A typo in `disable` suppresses nothing,
which reads exactly like a rule that never fires — so without the warning you
would believe a check was switched off when it was running, or running when it
was off.

## Precedence

Command-line flags beat the config file, which beats the defaults.

| Setting | Flag |
| --- | --- |
| `failOn` | `--fail-on <level>` |
| `includePossibleAgents` | `--strict-agents` |

## Where the file is looked for

At the root you pass to `promptfence`. Scanning a single file looks in that
file's directory. Scanning a repository root looks there, not in
`.github/workflows`.
