import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { RULES, ruleById } from '../src/rules/catalog.ts';
import { compareSeverity } from '../src/types.ts';
import { analyse, findingFor, ruleIds, severityOf, workflow } from './helpers.ts';

const AGENT_STEP = `      - uses: anthropics/claude-code-action@v1
        with:
          prompt: 'Handle this: \${{ github.event.issue.body }}'`;

describe('the rule catalogue', () => {
  it('has complete descriptors', () => {
    for (const rule of RULES) {
      assert.match(rule.id, /^[a-z][a-z-]+[a-z]$/, rule.id);
      assert.ok(rule.title.length > 10, rule.id);
      assert.ok(rule.rationale.length > 60, `${rule.id} needs a rationale worth reading`);
      assert.ok(rule.remediation.length > 20, `${rule.id} must say what to change`);
    }
  });

  it('has unique ids and can look them up', () => {
    assert.equal(new Set(RULES.map((rule) => rule.id)).size, RULES.length);
    assert.equal(ruleById('untrusted-checkout-with-agent')?.defaultSeverity, 'critical');
    assert.equal(ruleById('no-such-rule'), undefined);
  });
});

describe('severity depends on the trigger', () => {
  it('rates the same interpolation far higher on a privileged trigger', () => {
    const privileged = analyse(workflow({ on: 'issue_comment', steps: AGENT_STEP }));
    const forkOnly = analyse(workflow({ on: 'pull_request', steps: AGENT_STEP }));

    const a = severityOf(privileged, 'agent-reads-interpolated-input');
    const b = severityOf(forkOnly, 'agent-reads-interpolated-input');

    assert.ok(a !== undefined && b !== undefined);
    assert.ok(
      compareSeverity(a, b) < 0,
      `expected ${a} on issue_comment to outrank ${b} on pull_request`,
    );
  });

  it('says out loud that a fork pull_request cannot reach much', () => {
    const forkOnly = analyse(workflow({ on: 'pull_request', steps: AGENT_STEP }));
    const finding = findingFor(forkOnly, 'agent-reads-interpolated-input');
    assert.match(finding?.consequence ?? '', /without repository secrets/);
  });

  it('names what an attacker gets when the trigger is privileged', () => {
    const analysis = analyse(
      workflow({ on: 'issue_comment', jobPermissions: '{ contents: write, id-token: write }', steps: AGENT_STEP }),
    );
    const finding = findingFor(analysis, 'agent-reads-interpolated-input');
    assert.match(finding?.consequence ?? '', /push commits/);
    assert.match(finding?.consequence ?? '', /OIDC/);
  });
});

describe('rules', () => {
  it('finds an agent that ingests the event with no interpolation at all', () => {
    // The workflow passes nothing. The action reads the payload itself, which
    // is the case a search for ${{ }} cannot find.
    const analysis = analyse(
      workflow({
        on: 'issue_comment',
        steps: `      - uses: anthropics/claude-code-action@v1
        with:
          prompt: 'Triage the report'`,
      }),
    );
    assert.ok(ruleIds(analysis).includes('agent-ingests-untrusted-event'));
  });

  it('does not fire the ingest rule on a trigger with no outsider content', () => {
    const analysis = analyse(workflow({ on: 'schedule' }));
    assert.ok(!ruleIds(analysis).includes('agent-ingests-untrusted-event'));
  });

  it('rates a privileged checkout of contributor code as critical', () => {
    const analysis = analyse(
      workflow({
        on: 'pull_request_target',
        jobPermissions: '{ contents: write }',
        steps: `      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: claude -p 'review the diff'`,
      }),
    );
    assert.equal(severityOf(analysis, 'untrusted-checkout-with-agent'), 'critical');
  });

  it('does not fire the checkout rule without a privileged trigger', () => {
    const analysis = analyse(
      workflow({
        on: 'pull_request',
        steps: `      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: claude -p 'review the diff'`,
      }),
    );
    assert.ok(!ruleIds(analysis).includes('untrusted-checkout-with-agent'));
  });

  it('reports a fetch of outsider text into an agent job', () => {
    const analysis = analyse(
      workflow({
        on: 'issue_comment',
        steps: `      - run: gh issue view 1 --comments > /tmp/c.md
      - run: claude -p "$(cat /tmp/c.md)"`,
      }),
    );
    assert.ok(ruleIds(analysis).includes('agent-fetches-untrusted-content'));
  });

  it('reports write permissions only for scopes that are hard to undo', () => {
    const dangerous = analyse(workflow({ jobPermissions: '{ contents: write }' }));
    assert.ok(ruleIds(dangerous).includes('agent-holds-write-permissions'));

    const mild = analyse(workflow({ jobPermissions: '{ issues: write, pull-requests: write }' }));
    assert.ok(!ruleIds(mild).includes('agent-holds-write-permissions'));
  });

  it('does not treat the model key as an extra secret in scope', () => {
    // Every agent needs one. A finding that included it would fire on every
    // agent workflow ever written, including the correct ones.
    const analysis = analyse(
      workflow({
        jobPermissions: '{}',
        steps: `      - uses: anthropics/claude-code-action@v1
        env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}`,
      }),
    );
    assert.ok(!ruleIds(analysis).includes('agent-holds-secrets'));
  });

  it('does report secrets that have nothing to do with the model', () => {
    const analysis = analyse(
      workflow({
        jobPermissions: '{}',
        steps: `      - uses: anthropics/claude-code-action@v1
        env:
          NPM_TOKEN: \${{ secrets.NPM_TOKEN }}`,
      }),
    );
    assert.ok(ruleIds(analysis).includes('agent-holds-secrets'));
  });

  it('reports an unset permissions block', () => {
    assert.ok(ruleIds(analyse(workflow({}))).includes('agent-permissions-unset'));
    assert.ok(!ruleIds(analyse(workflow({ jobPermissions: '{}' }))).includes('agent-permissions-unset'));
  });

  it('reports an unpinned agent action and accepts a commit pin', () => {
    assert.ok(ruleIds(analyse(workflow({}))).includes('unpinned-agent-action'));

    const pinned = analyse(
      workflow({ steps: `      - uses: anthropics/claude-code-action@${'a'.repeat(40)}` }),
    );
    assert.ok(!ruleIds(pinned).includes('unpinned-agent-action'));
  });

  it('reports secrets: inherit into an agent workflow', () => {
    const analysis = analyse(
      [
        'name: t',
        'on:',
        '  issue_comment:',
        'jobs:',
        '  agent:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: anthropics/claude-code-action@v1',
        '    secrets: inherit',
        '',
      ].join('\n'),
    );
    assert.ok(ruleIds(analysis).includes('agent-inherits-all-secrets'));
  });

  it('stays completely silent on a workflow doing everything right', () => {
    // A rule that fires here is a rule that fires everywhere.
    const analysis = analyse(
      [
        'name: nightly',
        'on:',
        '  schedule:',
        '    - cron: "0 3 * * *"',
        'permissions: {}',
        'jobs:',
        '  tidy:',
        '    runs-on: ubuntu-latest',
        '    permissions:',
        '      pull-requests: write',
        '    steps:',
        `      - uses: anthropics/claude-code-base-action@${'a'.repeat(40)}`,
        '        with:',
        "          prompt: 'Fix typos in docs/'",
        '        env:',
        '          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
        '',
      ].join('\n'),
    );
    assert.deepEqual(ruleIds(analysis), []);
  });

  it('reports nothing at all on a workflow with no agent', () => {
    const analysis = analyse(
      [
        'name: ci',
        'on:',
        '  pull_request_target:',
        'permissions:',
        '  contents: write',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
        '      - run: npm ci && npm test',
        '',
      ].join('\n'),
    );
    // This workflow has a real problem, and it is zizmor's problem. Reporting
    // it here would be duplicating a mature tool badly.
    assert.deepEqual(ruleIds(analysis), []);
  });
});

describe('parse failures', () => {
  it('marks a workflow that will not parse as unanalysable, not as clean', () => {
    const analysis = analyse('name: t\non:\n  push:\njobs:\n  a: &anchor\n    runs-on: x\n');
    assert.equal(analysis.unanalysable || analysis.errors.length > 0, true);
  });

  it('never reports findings for an unanalysable workflow', () => {
    const analysis = analyse(': : :\n\t- broken');
    if (analysis.unanalysable) assert.deepEqual(analysis.findings, []);
  });
});
