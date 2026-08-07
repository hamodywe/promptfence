## What and why

<!-- What changes, and what problem it solves. The diff already says what; this
     is the place for why. -->

Closes #

## Checks

- [ ] `npm run typecheck` is clean
- [ ] `npm test` is green
- [ ] `npm run build` succeeds

## House rules

- [ ] No new runtime dependencies (`dependencies` in package.json is still empty)
- [ ] No network access, no LLM call, no timestamps in output — the same input
      still produces byte-identical output
- [ ] Nothing in a scanned workflow is executed

## If this changes what the tool reports

- [ ] Tests cover both the privileged trigger and the fork-only `pull_request`
      case — severity has to differ, and a rule that ignores the distinction is
      a rule that cries wolf
- [ ] `examples/.github/workflows/nightly-docs.yml` still produces **zero**
      findings. A rule that fires on the correct fixture fires everywhere
- [ ] The no-agent fixture still produces zero findings — general workflow
      security is zizmor's job, not this tool's
- [ ] `docs/rules.md` and the README rule table updated
- [ ] Any new gap is written into the README's limitations section in this same
      pull request

## If this changes the `--json` report

- [ ] Fields were added, not removed or retyped — or `schemaVersion` was
      incremented and the CHANGELOG says so
