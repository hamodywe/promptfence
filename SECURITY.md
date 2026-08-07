# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/hamodywe/promptfence/security/advisories/new)
rather than as a public issue.

Expect an acknowledgement within 72 hours and an assessment within seven days.
If a fix is warranted, you will be credited in the advisory unless you ask not
to be.

## Supported versions

The latest minor release receives security fixes. This project is pre-1.0; when
it reaches 1.0 this section will name a support window.

## What counts as a vulnerability in this tool

promptfence reads hostile input by design — it is pointed at repositories,
including forks and untrusted pull requests. The following are in scope:

- **Code execution while scanning.** Nothing in a workflow file should ever be
  executed. Expressions are parsed as strings, never evaluated.
- **Denial of service in the parser.** A crafted workflow that makes a scan hang
  or exhaust memory. YAML alias expansion is the classic form; this parser has
  no alias mechanism at all, so a working exponential-expansion input would be a
  serious finding. Catastrophic regular-expression backtracking is also in
  scope.
- **Path traversal.** Discovery reads workflow files under the given path. A
  construction that gets it to read outside is in scope.
- **Report injection.** Output that lets a scanned workflow forge findings —
  terminal escape sequences that rewrite the screen, markdown that breaks out of
  a table cell, SARIF that misattributes a result to a file the attacker chose.
- **Silent under-reporting.** A *general technique* for hiding an agent step or
  an untrusted source from the analysis. This is the one worth stressing:
  because the tool is used as a gate, a reliable way to make a workflow look
  clean is more valuable to an attacker than making it crash.

## What does not count

- **A missed agent in one workflow.** The catalogue will always trail the
  ecosystem. Please open a
  [false finding](https://github.com/hamodywe/promptfence/issues/new?template=false_finding.yml)
  issue — those are welcome and genuinely useful, they are just not security
  reports.
- **A false positive.** Same.
- **Vulnerabilities in workflows promptfence reports on.** Report those to the
  repository's maintainers. promptfence is the messenger.
- **Documented limitations.** Reusable workflows and composite actions are not
  followed, and `if:` conditions are not modelled. These are stated in the
  README. Improving them is a feature request.

## This tool's own security posture

- **No network access.** There is none anywhere in the tool. It works in an
  air-gapped build and cannot exfiltrate what it reads.
- **Nothing is executed.** Workflow expressions are parsed as text. Shell
  commands in `run:` blocks are scanned as strings and never passed to a shell.
- **No LLM.** The analysis is entirely static, which is also why it is
  deterministic.
- **Zero runtime dependencies.** The published package has no `dependencies`, so
  installing it does not widen your supply chain.
- **A deliberately restricted YAML parser.** Anchors, aliases, merge keys and
  tags are refused rather than implemented. The billion-laughs class of attack
  is structurally impossible rather than mitigated, and a workflow using those
  features is reported as unanalysable rather than analysed wrongly.
- **No install script.** promptfence does not need one.
- **Read-only.** promptfence never writes to the repository it scans.

## A note on the example workflows

`examples/.github/workflows/` contains deliberately vulnerable workflows. They
exist so the tool has something to find and so the test suite can assert on it.

They are under `examples/` and not at the repository root, so GitHub does not
run them, and every one carries a header saying what is wrong with it. If you
are looking for a workflow to copy, copy `nightly-docs.yml` — it is the one that
is correct.
