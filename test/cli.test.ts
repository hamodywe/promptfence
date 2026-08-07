import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { parseArgs, UsageError } from '../src/cli/args.ts';
import { helpText } from '../src/cli/help.ts';
import { DEFAULT_CONFIG, isExcluded, parseConfig } from '../src/config.ts';
import { evaluateGate } from '../src/gate.ts';
import { renderJson } from '../src/report/json.ts';
import { renderMarkdown } from '../src/report/markdown.ts';
import { renderSarif } from '../src/report/sarif.ts';
import { renderTerminal } from '../src/report/terminal.ts';
import { RULES } from '../src/rules/catalog.ts';
import { scan } from '../src/scan.ts';
import { captureStream } from './helpers.ts';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXAMPLES = path.join(REPO_ROOT, 'examples');

/**
 * Run the CLI as a real process.
 *
 * Capturing output by replacing `process.stdout.write` corrupts the test
 * runner's own output, which writes to the same stream. Spawning costs a little
 * time and tests what users actually run, exit code included.
 */
function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [path.join(REPO_ROOT, 'src', 'cli.ts'), ...argv],
      { cwd: REPO_ROOT, env: { ...process.env, NO_COLOR: '1' }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number') {
          reject(error);
          return;
        }
        resolve({ code: typeof error?.code === 'number' ? error.code : 0, stdout, stderr });
      },
    );
  });
}

describe('argument parsing', () => {
  it('defaults to scanning the working directory', () => {
    const parsed = parseArgs([]);
    assert.equal(parsed.args?.command, 'scan');
    assert.equal(parsed.args?.root, '.');
  });

  it('reads commands, paths and formats', () => {
    assert.equal(parseArgs(['check', 'repo']).args?.command, 'check');
    assert.equal(parseArgs(['check', 'repo']).args?.root, 'repo');
    assert.equal(parseArgs(['--sarif']).args?.format, 'sarif');
    assert.equal(parseArgs(['--md']).args?.format, 'markdown');
  });

  it('treats a bare path as a scan target, not a command', () => {
    assert.equal(parseArgs(['some-repo']).args?.command, 'scan');
    assert.equal(parseArgs(['some-repo']).args?.root, 'some-repo');
  });

  it('accepts --fail-on with a space or an equals sign', () => {
    assert.equal(parseArgs(['--fail-on', 'low']).args?.failOn, 'low');
    assert.equal(parseArgs(['--fail-on=critical']).args?.failOn, 'critical');
  });

  it('rejects unknown options and bad values rather than ignoring them', () => {
    assert.throws(() => parseArgs(['--nope']), UsageError);
    assert.throws(() => parseArgs(['--fail-on', 'severe']), UsageError);
    assert.throws(() => parseArgs(['scan', 'a', 'b']), UsageError);
  });

  it('takes a rule id for the rules command', () => {
    assert.equal(parseArgs(['rules', 'unpinned-agent-action']).args?.ruleId, 'unpinned-agent-action');
    assert.equal(parseArgs(['rules']).args?.ruleId, undefined);
  });

  it('handles help and version first', () => {
    assert.equal(parseArgs(['--help']).kind, 'help');
    assert.equal(parseArgs(['--version']).kind, 'version');
    assert.equal(parseArgs(['check', '--help']).helpFor, 'check');
  });

  it('has help text for every command', () => {
    for (const command of ['scan', 'check', 'rules'] as const) {
      assert.ok(helpText(command).length > 100, command);
    }
  });
});

describe('configuration', () => {
  it('falls back with a warning on bad JSON', () => {
    const { config, warnings } = parseConfig('{oops');
    assert.deepEqual(config, DEFAULT_CONFIG);
    assert.equal(warnings.length, 1);
  });

  it('rejects an unknown rule id instead of silently suppressing nothing', () => {
    const { config, warnings } = parseConfig('{"disable":["no-such-rule","unpinned-agent-action"]}');
    assert.deepEqual(config.disable, ['unpinned-agent-action']);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? '', /unknown rule/);
  });

  it('reads valid settings', () => {
    const { config, warnings } = parseConfig(
      '{"failOn":"critical","warnOnly":["agent-holds-secrets"],"exclude":["ci.yml"],"includePossibleAgents":false}',
    );
    assert.equal(config.failOn, 'critical');
    assert.deepEqual(config.warnOnly, ['agent-holds-secrets']);
    assert.equal(config.includePossibleAgents, false);
    assert.deepEqual(warnings, []);
  });

  it('excludes by exact path or by basename', () => {
    const config = { ...DEFAULT_CONFIG, exclude: ['nightly.yml'] };
    assert.equal(isExcluded(config, '.github/workflows/nightly.yml'), true);
    assert.equal(isExcluded(config, 'nightly.yml'), true);
    assert.equal(isExcluded(config, '.github/workflows/ci.yml'), false);
  });
});

describe('the example workflows', () => {
  it('finds what the fixture comments say it will', async () => {
    const { report } = await scan({ root: EXAMPLES });
    const byPath = new Map(report.workflows.map((workflow) => [workflow.path, workflow]));

    const triage = byPath.get('.github/workflows/issue-triage.yml');
    const rules = triage?.findings.map((finding) => finding.ruleId) ?? [];
    assert.ok(rules.includes('agent-ingests-untrusted-event'));
    assert.ok(rules.includes('agent-reads-interpolated-input'));
    assert.ok(triage?.findings.some((finding) => finding.severity === 'critical'));

    const review = byPath.get('.github/workflows/pr-review.yml');
    assert.ok(review?.findings.some((finding) => finding.ruleId === 'untrusted-checkout-with-agent'));

    // The clean fixture must stay clean. A rule that fires here fires everywhere.
    assert.deepEqual(byPath.get('.github/workflows/nightly-docs.yml')?.findings, []);
  });

  it('rates the fork-only workflow below the privileged one', async () => {
    const { report } = await scan({ root: EXAMPLES });
    const byPath = new Map(report.workflows.map((workflow) => [workflow.path, workflow]));

    const fork = byPath
      .get('.github/workflows/fork-safe.yml')
      ?.findings.find((finding) => finding.ruleId === 'agent-reads-interpolated-input');
    const privileged = byPath
      .get('.github/workflows/issue-triage.yml')
      ?.findings.find((finding) => finding.ruleId === 'agent-reads-interpolated-input');

    assert.equal(fork?.severity, 'medium');
    assert.equal(privileged?.severity, 'critical');
  });

  it('produces the same report twice', async () => {
    const first = renderJson((await scan({ root: EXAMPLES })).report);
    const second = renderJson((await scan({ root: EXAMPLES })).report);
    assert.equal(first, second);
  });

  it('drops possible agents under --strict-agents', async () => {
    const loose = await scan({ root: EXAMPLES, includePossibleAgents: true });
    const strict = await scan({ root: EXAMPLES, includePossibleAgents: false });
    assert.ok(strict.report.summary.findings <= loose.report.summary.findings);
  });
});

describe('the gate', () => {
  it('fails on the example workflows and groups the reasons by rule', async () => {
    const { report, config } = await scan({ root: EXAMPLES });
    const gate = evaluateGate(report, config);

    assert.equal(gate.passed, false);
    assert.ok(gate.reasons.length > 0);
    assert.equal(new Set(gate.reasons).size, gate.reasons.length, 'reasons should not repeat');
  });

  it('honours warnOnly without letting the finding disappear', async () => {
    const { report, config } = await scan({ root: EXAMPLES });
    const waivedRules = ['untrusted-checkout-with-agent'];

    const gate = evaluateGate(report, { ...config, warnOnly: waivedRules });
    assert.ok(gate.waived.some((finding) => waivedRules.includes(finding.ruleId)));
    assert.ok(!gate.reasons.some((reason) => reason.includes('untrusted-checkout-with-agent')));
  });

  it('respects a threshold override', async () => {
    const { report, config } = await scan({ root: EXAMPLES });
    const strict = evaluateGate(report, config, { failOn: 'info' });
    const lenient = evaluateGate(report, config, { failOn: 'critical' });
    assert.ok(strict.reasons.length >= lenient.reasons.length);
  });
});

describe('reporters', () => {
  it('emits JSON that declares its schema', async () => {
    const { report, warnings } = await scan({ root: EXAMPLES });
    const payload = JSON.parse(renderJson(report, { warnings }));

    assert.equal(payload.schemaVersion, 1);
    assert.equal(payload.tool.name, 'promptfence');
    assert.equal(payload.workflows.length, report.workflows.length);
    assert.ok(payload.workflows.every((workflow: { path: string }) => !path.isAbsolute(workflow.path)));
  });

  it('emits valid SARIF whose results all have declared rules', async () => {
    const { report } = await scan({ root: EXAMPLES });
    const sarif = JSON.parse(renderSarif(report));

    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.rules.length, RULES.length);

    const declared = new Set(sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id));
    assert.ok(sarif.runs[0].results.length > 0);
    for (const result of sarif.runs[0].results) {
      assert.ok(declared.has(result.ruleId), `undeclared rule: ${result.ruleId}`);
      assert.ok(['error', 'warning', 'note'].includes(result.level));
      assert.ok(result.locations[0].physicalLocation.region.startLine >= 1);
    }
  });

  it('escapes pipes so a message cannot break a markdown table', async () => {
    const { report } = await scan({ root: EXAMPLES });
    const markdown = renderMarkdown(report);

    for (const line of markdown.split('\n').filter((line) => line.startsWith('| '))) {
      assert.equal(line.split(/(?<!\\)\|/).length, 6, `unexpected cell count in: ${line}`);
    }
  });

  it('writes plain text when the stream is not a terminal', async () => {
    const { report } = await scan({ root: EXAMPLES });
    const text = renderTerminal(report, captureStream());

    assert.ok(!text.includes('['), 'expected no ANSI escapes');
    assert.match(text, /issue-triage/);
  });
});

describe('the command line, end to end', () => {
  it('prints the version and the help', async () => {
    const version = await run(['--version']);
    assert.equal(version.code, 0);
    assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/);

    const help = await run(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /promptfence/);
  });

  it('exits 2 on bad usage', async () => {
    const { code, stderr } = await run(['--nope']);
    assert.equal(code, 2);
    assert.match(stderr, /unknown option/);
  });

  it('exits 2 when the path holds no workflows', async () => {
    const { code, stderr } = await run(['scan', path.join(REPO_ROOT, 'src')]);
    assert.equal(code, 2);
    assert.match(stderr, /no workflows/);
  });

  it('exits 2 for a path that does not exist', async () => {
    const { code, stderr } = await run(['scan', path.join(REPO_ROOT, 'nowhere')]);
    assert.equal(code, 2);
    assert.match(stderr, /no such file or directory/);
  });

  it('scans the examples and exits 0', async () => {
    const { code, stdout } = await run(['scan', EXAMPLES]);
    assert.equal(code, 0);
    assert.match(stdout, /run an AI agent/);
  });

  it('fails the check on the examples', async () => {
    const { code, stderr } = await run(['check', EXAMPLES, '--quiet']);
    assert.equal(code, 1);
    assert.match(stderr, /promptfence: fail/);
  });

  it('keeps JSON on stdout clean while the verdict goes to stderr', async () => {
    const { code, stdout, stderr } = await run(['check', EXAMPLES, '--json']);
    assert.equal(code, 1);
    assert.doesNotThrow(() => JSON.parse(stdout));
    assert.match(stderr, /fail/);
  });

  it('accepts a single workflow file', async () => {
    const { code, stdout } = await run([
      'scan',
      path.join(EXAMPLES, '.github', 'workflows', 'nightly-docs.yml'),
    ]);
    assert.equal(code, 0);
    assert.match(stdout, /1 workflows/);
  });

  it('lists the rules and explains one', async () => {
    const list = await run(['rules']);
    assert.equal(list.code, 0);
    for (const rule of RULES) assert.match(list.stdout, new RegExp(rule.id));

    const one = await run(['rules', 'untrusted-checkout-with-agent']);
    assert.equal(one.code, 0);
    assert.match(one.stdout, /Why it matters/);

    const missing = await run(['rules', 'no-such-rule']);
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /no such rule/);
  });
});
