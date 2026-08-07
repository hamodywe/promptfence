import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { detectAgents, isModelKeyName } from '../src/analysis/agents.ts';
import {
  carriesUntrustedContent,
  expressionsIn,
  fetchCommandsIn,
  isPrivilegedTrigger,
  untrustedReferencesIn,
} from '../src/analysis/contexts.ts';
import {
  checksOutUntrustedCode,
  computeBlastRadius,
  resolvePermissions,
  runsSelfHosted,
  secretsInScope,
} from '../src/analysis/blast.ts';
import { isPinnedToSha, parseWorkflow, splitActionRef } from '../src/workflow/model.ts';

function job(yaml: string) {
  const parsed = parseWorkflow(yaml, 'test.yml');
  return { workflow: parsed, job: parsed.jobs[0]! };
}

describe('trigger posture', () => {
  it('knows which events carry outsider-written content', () => {
    for (const event of ['issues', 'issue_comment', 'pull_request', 'pull_request_target', 'discussion']) {
      assert.equal(carriesUntrustedContent(event), true, event);
    }
    for (const event of ['push', 'schedule', 'workflow_dispatch', 'release']) {
      assert.equal(carriesUntrustedContent(event), false, event);
    }
  });

  it('separates fork pull_request from the triggers that hand out secrets', () => {
    // This is the distinction the whole severity model rests on. A fork's
    // pull_request has a read-only token and no secrets; the others do not.
    assert.equal(isPrivilegedTrigger('pull_request'), false);

    for (const event of [
      'pull_request_target',
      'issue_comment',
      'issues',
      'workflow_run',
      'discussion_comment',
      'pull_request_review',
    ]) {
      assert.equal(isPrivilegedTrigger(event), true, event);
    }
  });
});

describe('untrusted context detection', () => {
  it('extracts expressions', () => {
    assert.deepEqual(expressionsIn('a ${{ github.actor }} b ${{ inputs.x }}'), [
      'github.actor',
      'inputs.x',
    ]);
    assert.deepEqual(expressionsIn('no expressions here'), []);
  });

  it('finds the obvious sources', () => {
    for (const text of [
      '${{ github.event.issue.body }}',
      '${{ github.event.comment.body }}',
      '${{ github.event.pull_request.title }}',
      '${{ github.event.review.body }}',
    ]) {
      assert.equal(untrustedReferencesIn(text).length, 1, text);
    }
  });

  it('finds a branch name, which is free text people forget about', () => {
    const found = untrustedReferencesIn('${{ github.head_ref }}');
    assert.equal(found.length, 1);
    assert.match(found[0]?.control ?? '', /branch name/);
  });

  it('leaves trusted context alone', () => {
    for (const text of [
      '${{ github.repository }}',
      '${{ github.sha }}',
      '${{ secrets.TOKEN }}',
      '${{ github.event.pull_request.number }}',
      '${{ inputs.environment }}',
    ]) {
      assert.deepEqual(untrustedReferencesIn(text), [], text);
    }
  });

  it('finds a reference without interpolation braces', () => {
    // A prompt template that names the context in prose reaches the model just
    // as effectively as one that interpolates it.
    assert.equal(untrustedReferencesIn('Read github.event.issue.body carefully').length, 1);
  });

  it('finds commands that go and fetch outsider text', () => {
    assert.equal(fetchCommandsIn('gh pr view 12 --comments').length, 1);
    assert.equal(fetchCommandsIn('gh issue view "$N"').length, 1);
    assert.equal(fetchCommandsIn('gh api repos/o/r/issues/1/comments').length, 1);
    assert.equal(fetchCommandsIn('npm test').length, 0);
    assert.equal(fetchCommandsIn('gh release create v1').length, 0);
  });
});

describe('agent detection', () => {
  function agentsIn(steps: string) {
    const { job: parsed } = job(`name: t\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n${steps}\n`);
    return detectAgents('a', parsed.steps);
  }

  it('recognises a known agent action with certainty', () => {
    const found = agentsIn('      - uses: anthropics/claude-code-action@v1');
    assert.equal(found.length, 1);
    assert.equal(found[0]?.confidence, 'certain');
    assert.equal(found[0]?.product, 'claude-code-action');
    assert.equal(found[0]?.ingestsEvent, true);
  });

  it('recognises an agent CLI in a run block', () => {
    const found = agentsIn("      - run: claude -p 'review this'");
    assert.equal(found[0]?.confidence, 'likely');
    assert.equal(found[0]?.product, 'claude code');
  });

  it('falls back to a model key with the confidence that implies', () => {
    const found = agentsIn(
      '      - run: node ./scripts/review.js\n        env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
    );
    assert.equal(found[0]?.confidence, 'possible');
    assert.equal(found[0]?.product, null);
  });

  it('does not call an ordinary step an agent', () => {
    assert.deepEqual(agentsIn('      - uses: actions/checkout@v4'), []);
    assert.deepEqual(agentsIn('      - run: npm ci && npm test'), []);
    // "claude" appearing as a word is not an invocation.
    assert.deepEqual(agentsIn('      - run: echo "ask claude about it later"'), []);
  });

  it('notices when an agent action is not pinned', () => {
    assert.equal(agentsIn('      - uses: anthropics/claude-code-action@v1')[0]?.unpinned, true);
    assert.equal(
      agentsIn(`      - uses: anthropics/claude-code-action@${'a'.repeat(40)}`)[0]?.unpinned,
      false,
    );
  });

  it('knows which secret names are model keys', () => {
    assert.equal(isModelKeyName('ANTHROPIC_API_KEY'), true);
    assert.equal(isModelKeyName('OPENAI_API_KEY'), true);
    assert.equal(isModelKeyName('NPM_TOKEN'), false);
  });
});

describe('action references', () => {
  it('splits a reference from its version', () => {
    assert.deepEqual(splitActionRef('owner/repo@v1'), { action: 'owner/repo', ref: 'v1' });
    assert.deepEqual(splitActionRef('./.github/actions/local'), {
      action: './.github/actions/local',
      ref: null,
    });
  });

  it('recognises a commit pin', () => {
    assert.equal(isPinnedToSha('a'.repeat(40)), true);
    assert.equal(isPinnedToSha('v4'), false);
    assert.equal(isPinnedToSha('main'), false);
    assert.equal(isPinnedToSha(null), false);
  });
});

describe('permissions resolution', () => {
  const base = 'name: t\non:\n  push:\n';

  it('expands write-all', () => {
    const { workflow, job: parsed } = job(
      `${base}permissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`,
    );
    const resolved = resolvePermissions(workflow, parsed);
    assert.ok(resolved.writeScopes.includes('contents'));
    assert.ok(resolved.writeScopes.includes('id-token'));
    assert.equal(resolved.unset, false);
  });

  it('treats read-all as granting no writes', () => {
    const { workflow, job: parsed } = job(
      `${base}permissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`,
    );
    assert.deepEqual(resolvePermissions(workflow, parsed).writeScopes, []);
  });

  it('lets a job block replace the workflow block rather than merge with it', () => {
    const { workflow, job: parsed } = job(
      `${base}permissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      issues: write\n    steps: []\n`,
    );
    assert.deepEqual(resolvePermissions(workflow, parsed).writeScopes, ['issues']);
  });

  it('reports an absent block as unset rather than guessing', () => {
    const { workflow, job: parsed } = job(`${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`);
    const resolved = resolvePermissions(workflow, parsed);
    assert.equal(resolved.unset, true);
    assert.deepEqual(resolved.writeScopes, []);
  });

  it('distinguishes an empty block from an absent one', () => {
    const { workflow, job: parsed } = job(
      `${base}permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`,
    );
    assert.equal(resolvePermissions(workflow, parsed).unset, false);
  });
});

describe('blast radius', () => {
  const base = 'name: t\non:\n  push:\n';

  it('collects secrets and leaves GITHUB_TOKEN out', () => {
    const { workflow, job: parsed } = job(
      `${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: deploy\n        env:\n          A: \${{ secrets.NPM_TOKEN }}\n          B: \${{ secrets.GITHUB_TOKEN }}\n          C: \${{ secrets.AWS_KEY }}\n`,
    );
    assert.deepEqual(secretsInScope(workflow, parsed), ['AWS_KEY', 'NPM_TOKEN']);
  });

  it('separates the model key from the other secrets', () => {
    const { workflow, job: parsed } = job(
      `${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: claude -p x\n        env:\n          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}\n          NPM_TOKEN: \${{ secrets.NPM_TOKEN }}\n`,
    );
    const blast = computeBlastRadius(workflow, parsed);
    assert.deepEqual(blast.secrets, ['NPM_TOKEN']);
    assert.deepEqual(blast.modelKeys, ['ANTHROPIC_API_KEY']);
  });

  it('records secrets: inherit as its own thing', () => {
    const { workflow, job: parsed } = job(
      `${base}jobs:\n  a:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n`,
    );
    assert.ok(computeBlastRadius(workflow, parsed).secrets.includes('*inherit*'));
  });

  it('spots a checkout of the contributor’s code', () => {
    const withRef = job(
      `${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`,
    );
    assert.equal(checksOutUntrustedCode(withRef.job), true);

    const plain = job(
      `${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n`,
    );
    assert.equal(checksOutUntrustedCode(plain.job), false);
  });

  it('spots a self-hosted runner in either form', () => {
    assert.equal(
      runsSelfHosted(job(`${base}jobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps: []\n`).job),
      true,
    );
    assert.equal(
      runsSelfHosted(job(`${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`).job),
      false,
    );
  });

  it('scores an unset permissions block above an explicitly empty one', () => {
    const unset = job(`${base}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`);
    const empty = job(`${base}permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n`);

    assert.ok(
      computeBlastRadius(unset.workflow, unset.job).score >
        computeBlastRadius(empty.workflow, empty.job).score,
      'an unset block means "whatever the repository default is", which is not nothing',
    );
  });
});
