# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The `--json` report carries a `schemaVersion`. Anything that would break a
consumer reading it — removing a field, changing a type, changing what a value
means — increments that number and is listed here as a breaking change. Adding a
field does not, so consumers should ignore keys they do not recognise.

## [Unreleased]

## [0.1.0] — 2026-08-07

First release.

### Added

- `scan` — analyse GitHub Actions workflows for AI agent steps, work out where
  outsider-controlled text can reach them, and report what the surrounding job
  is permitted to do.
- `check` — a CI gate that fails on findings at or above a severity, and on any
  workflow that could not be parsed.
- `rules` — list the rule catalogue, or print one rule in full.
- Ten rules, from `untrusted-checkout-with-agent` (critical) to
  `unpinned-agent-action` (low), each stating a consequence rather than a policy.
- Severity that follows the trigger: `pull_request` from a fork has a read-only
  token and no secrets, so the same construction is rated far below the same
  line under `pull_request_target`, `issue_comment` or `workflow_run`.
- Detection of agents that read the triggering event by design — the case with
  no `${{ }}` to find, and the one a template-injection linter cannot see.
- Layered agent detection with stated confidence: known actions (`certain`),
  known CLIs in `run:` blocks (`likely`), and a model provider key in scope with
  no recognised agent (`possible`, disableable with `--strict-agents`).
- Blast radius per job: resolved write scopes, secrets excluding the model
  provider key, OIDC, checkout of contributor-controlled refs, self-hosted
  runners.
- Reporters: terminal, `--json`, `--markdown` for pull requests, and `--sarif`
  for GitHub code scanning.
- Optional `promptfence.config.json` for the fail threshold, warn-only rules,
  disabled rules and excluded workflows.
- A hand-written YAML parser covering the GitHub Actions subset, with no alias
  mechanism at all — so alias-expansion denial of service is structurally
  impossible rather than mitigated — and per-node line tracking so every finding
  points at a line rather than a file.

[Unreleased]: https://github.com/hamodywe/promptfence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hamodywe/promptfence/releases/tag/v0.1.0
