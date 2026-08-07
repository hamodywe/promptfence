# Contributing

Thank you for considering it. The most valuable contribution to this project is
not a feature — it is telling us when a verdict is wrong.

## The most useful issue you can open

A **false finding**, in either direction:

- a workflow flagged that is genuinely fine, or
- an agent step this tool failed to see at all.

The second is the more dangerous one. This space produces new agent actions and
wrappers faster than any catalogue keeps up, and a missed sink is a missed
finding with no trace in the output.

Use the [false finding template](.github/ISSUE_TEMPLATE/false_finding.yml) and
include the workflow, redacted as needed.

## Getting set up

```sh
git clone https://github.com/hamodywe/promptfence
cd promptfence
npm install
npm test
```

No build step for development. The CLI runs from source:

```sh
node src/cli.ts scan examples
```

Node 22.18 or newer is needed to run the TypeScript sources directly. The
published package is compiled and supports Node 20.10.

## Before opening a pull request

```sh
npm run typecheck   # must be clean
npm test            # must be green
npm run build       # must succeed
```

## House rules

**Zero runtime dependencies.** Not negotiable. A supply-chain security tool that
arrives with thirty transitive dependencies is making an argument against
itself. This includes the YAML parser: it is hand-written because a full YAML
implementation is a large attack surface on hostile input, and because
general-purpose parsers throw away the line numbers every finding depends on.

**Every finding states a consequence, not a policy.** "Do not interpolate
untrusted input" is advice. "An attacker who comments on any issue can make this
agent push to main" is a claim someone can check, disagree with, and act on. The
second kind gets fixed.

**Severity follows the trigger.** A fork's `pull_request` has a read-only token
and no secrets. Rating it the same as `pull_request_target` is not caution, it
is noise — and noise is what teaches people to ignore the real finding. Any new
rule has to say what it does on both.

**The clean fixture must stay clean.** `examples/.github/workflows/nightly-docs.yml`
is a correct agent workflow and the suite asserts it produces zero findings. A
rule that fires there would fire everywhere.

**Deterministic and offline.** No network, no timestamps in output, no
`Math.random`. Two scans of the same tree must produce byte-identical reports.

**Unanalysable is not clean.** Anything that cannot be parsed is reported as
such and fails `check`. "Found nothing" and "could not look" must never render
the same way.

**State limitations honestly.** If a change makes the tool better at something
but leaves a gap, the gap goes into the README's limitations section in the same
pull request.

## Adding a rule

1. Add a descriptor to `RULES` in `src/rules/catalog.ts`. The `rationale` is
   the part that matters: explain why someone should care, in terms of what an
   attacker gets.
2. Emit it from `evaluateJob` in `src/rules/evaluate.ts`.
3. Decide how the trigger moves its severity, and write a test for both the
   privileged and the fork-only case.
4. Add a test proving it stays silent on the clean fixture.
5. Document it in `docs/rules.md` and in the README's rule table.

## Adding an agent to the catalogue

`KNOWN_AGENT_ACTIONS` and `AGENT_COMMANDS` in `src/analysis/agents.ts`.

The `ingestsEvent` flag is the important one: set it when the action reads the
triggering event's payload into its own context by design. That is what lets the
tool report the case where the workflow interpolates nothing and the agent still
ends up holding the comment that triggered it.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/). Types in use:
`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`,
`security`.

```
feat(agents): recognise the OpenHands action as ingesting the event

Explains why, not what. The diff already says what.
```

Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
