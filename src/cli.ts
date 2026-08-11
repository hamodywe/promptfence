#!/usr/bin/env node
/**
 * The command line.
 *
 * Parse, run one command, choose an exit code. Everything else is delegated, so
 * that a consumer embedding `scan()` gets exactly what the terminal shows.
 *
 * Exit codes are part of the interface:
 *   0  clean
 *   1  the gate failed
 *   2  bad usage, or a path that could not be read
 */

import { realpathSync } from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { parseArgs, UsageError, type ParsedArgs } from './cli/args.ts';
import { helpText } from './cli/help.ts';
import { evaluateGate } from './gate.ts';
import { RULES, ruleById } from './rules/catalog.ts';
import { renderJson } from './report/json.ts';
import { renderMarkdown } from './report/markdown.ts';
import { renderSarif } from './report/sarif.ts';
import { createStyler, padEnd } from './report/style.ts';
import { renderTerminal } from './report/terminal.ts';
import { scan, VERSION, type ScanResult } from './scan.ts';

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;

export async function main(argv: readonly string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`promptfence: ${error.message}\n\nTry \`promptfence --help\`.\n`);
      return EXIT_USAGE;
    }
    throw error;
  }

  if (parsed.kind === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return EXIT_OK;
  }
  if (parsed.kind === 'help') {
    process.stdout.write(`${helpText(parsed.helpFor)}\n`);
    return EXIT_OK;
  }

  const args = parsed.args as ParsedArgs;

  if (args.command === 'rules') return runRules(args);

  let result: ScanResult;
  try {
    result = await scan({
      root: args.root,
      ...(args.includePossibleAgents !== undefined
        ? { includePossibleAgents: args.includePossibleAgents }
        : {}),
    });
  } catch (error) {
    process.stderr.write(`promptfence: ${(error as Error).message}\n`);
    return EXIT_USAGE;
  }

  if (!result.found) {
    process.stderr.write(
      `promptfence: no workflows found under ${args.root}.\n` +
        'Point it at a repository root, a .github/workflows directory, or a single workflow file.\n',
    );
    return EXIT_USAGE;
  }

  emitReport(args, result);

  if (args.command === 'check') {
    const gate = evaluateGate(result.report, result.config, {
      ...(args.failOn !== undefined ? { failOn: args.failOn } : {}),
    });

    // The verdict goes to stderr so `check --json > report.json` produces a
    // clean file and still shows the reason in the log.
    const style = createStyler(process.stderr);

    for (const waived of gate.waived) {
      process.stderr.write(
        `${style('dim', 'warn-only:')} ${waived.ruleId} at ${waived.workflow}:${waived.line}\n`,
      );
    }

    if (gate.passed) {
      process.stderr.write(
        `${style('green', 'promptfence: pass')} — nothing at or above ${gate.failOn}\n`,
      );
      return EXIT_OK;
    }

    process.stderr.write(`${style('red', 'promptfence: fail')}\n`);
    for (const reason of gate.reasons) process.stderr.write(`  · ${reason}\n`);
    process.stderr.write('\nRun `promptfence` for the detail, `promptfence rules <id>` for the reasoning.\n');
    return EXIT_FAILED;
  }

  return EXIT_OK;
}

function emitReport(args: ParsedArgs, result: ScanResult): void {
  const { report, warnings } = result;

  switch (args.format) {
    case 'json':
      process.stdout.write(renderJson(report, { warnings }));
      return;
    case 'markdown':
      process.stdout.write(renderMarkdown(report, { warnings }));
      return;
    case 'sarif':
      process.stdout.write(renderSarif(report));
      return;
    case 'terminal':
      process.stdout.write(
        renderTerminal(report, process.stdout, {
          verbose: args.verbose,
          quiet: args.quiet,
          warnings,
        }),
      );
  }
}

function runRules(args: ParsedArgs): number {
  const style = createStyler(process.stdout);

  if (args.ruleId !== undefined) {
    const rule = ruleById(args.ruleId);
    if (rule === undefined) {
      process.stderr.write(`promptfence: no such rule: ${args.ruleId}\n`);
      process.stderr.write(`Known rules: ${RULES.map((r) => r.id).join(', ')}\n`);
      return EXIT_FAILED;
    }

    if (args.format === 'json') {
      process.stdout.write(`${JSON.stringify(rule, null, 2)}\n`);
      return EXIT_OK;
    }

    process.stdout.write(
      [
        `${style('bold', rule.id)} ${style('dim', `(${rule.defaultSeverity} by default)`)}`,
        '',
        style('bold', rule.title),
        '',
        rule.summary,
        '',
        style('bold', 'Why it matters'),
        wrap(rule.rationale, 78, '  '),
        '',
        style('bold', 'What to change'),
        wrap(rule.remediation, 78, '  '),
        '',
      ].join('\n'),
    );
    return EXIT_OK;
  }

  if (args.format === 'json') {
    process.stdout.write(`${JSON.stringify(RULES, null, 2)}\n`);
    return EXIT_OK;
  }

  const width = Math.max(...RULES.map((rule) => rule.id.length));
  process.stdout.write(`${style('dim', `${padEnd('RULE', width)}  SEVERITY  TITLE`)}\n`);
  for (const rule of RULES) {
    process.stdout.write(
      `${style('cyan', padEnd(rule.id, width))}  ${padEnd(rule.defaultSeverity, 8)}  ${rule.title}\n`,
    );
  }
  process.stdout.write(
    `\n${style('dim', 'Severities shown are defaults. A privileged trigger raises them; a fork-only')}\n` +
      `${style('dim', 'pull_request lowers them. `promptfence rules <id>` explains each one.')}\n`,
  );
  return EXIT_OK;
}

/** Wrap prose to a column, for the long-form rule text. */
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = indent;

  for (const word of words) {
    if (current.length + word.length + 1 > width && current !== indent) {
      lines.push(current);
      current = indent + word;
    } else {
      current = current === indent ? indent + word : `${current} ${word}`;
    }
  }
  if (current !== indent) lines.push(current);

  return lines.join('\n');
}

// Run only when invoked as a program, so the fixture suite can import `main`.
// `pathToFileURL` is what makes this correct on Windows.
const entryPoint = process.argv[1];
// npm installs bins as symlinks and Node resolves the main module to its real
// path, so comparing against the raw argv[1] would never match on Linux or
// macOS — the CLI would print nothing and exit 0.
const entryUrl = (): string => {
  try {
    return pathToFileURL(realpathSync(entryPoint as string)).href;
  } catch {
    return pathToFileURL(entryPoint as string).href;
  }
};

const invokedDirectly = entryPoint !== undefined && import.meta.url === entryUrl();

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`promptfence: ${(error as Error).stack ?? String(error)}\n`);
      process.exitCode = EXIT_USAGE;
    },
  );
}
