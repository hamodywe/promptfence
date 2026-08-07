/**
 * Argument parsing.
 *
 * Hand-rolled, because the requirements are three commands and a handful of
 * flags. Unknown flags are errors rather than silent no-ops: a typo in
 * `--fail-on` that quietly leaves the default in place is how a gate stops
 * gating without anyone noticing.
 */

import { SEVERITIES, type Severity } from '../types.ts';

export const COMMANDS = ['scan', 'check', 'rules'] as const;
export type Command = (typeof COMMANDS)[number];

export type OutputFormat = 'terminal' | 'json' | 'markdown' | 'sarif';

export interface ParsedArgs {
  readonly command: Command;
  /** Repository root, workflows directory, or a single workflow file. */
  readonly root: string;
  /** `rules` only: show one rule in full. */
  readonly ruleId?: string;
  readonly format: OutputFormat;
  readonly failOn?: Severity;
  readonly verbose: boolean;
  readonly quiet: boolean;
  /** Report steps whose only agent evidence is a model API key in scope. */
  readonly includePossibleAgents?: boolean;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface ParseOutcome {
  readonly kind: 'args' | 'help' | 'version';
  readonly args?: ParsedArgs;
  readonly helpFor?: Command;
}

const FORMAT_FLAGS: Readonly<Record<string, OutputFormat>> = {
  '--json': 'json',
  '--markdown': 'markdown',
  '--md': 'markdown',
  '--sarif': 'sarif',
};

export function parseArgs(argv: readonly string[]): ParseOutcome {
  let command: Command = 'scan';
  let commandGiven = false;
  const positionals: string[] = [];

  let format: OutputFormat = 'terminal';
  let failOn: Severity | undefined;
  let verbose = false;
  let quiet = false;
  let includePossibleAgents: boolean | undefined;
  let help = false;
  let version = false;

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i] as string;

    if (token === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }

    if (!token.startsWith('-')) {
      if (!commandGiven && (COMMANDS as readonly string[]).includes(token)) {
        command = token as Command;
        commandGiven = true;
      } else {
        positionals.push(token);
      }
      continue;
    }

    const formatted = FORMAT_FLAGS[token];
    if (formatted !== undefined) {
      format = formatted;
      continue;
    }

    switch (token) {
      case '-h':
      case '--help':
        help = true;
        break;
      case '-v':
      case '--version':
        version = true;
        break;
      case '--verbose':
        verbose = true;
        break;
      case '-q':
      case '--quiet':
        quiet = true;
        break;
      case '--strict-agents':
        includePossibleAgents = false;
        break;
      case '--fail-on':
        failOn = readSeverity(argv[i + 1]);
        i += 1;
        break;
      default: {
        const equals = token.indexOf('=');
        if (equals > 0 && token.slice(0, equals) === '--fail-on') {
          failOn = readSeverity(token.slice(equals + 1));
          break;
        }
        throw new UsageError(`unknown option: ${token}`);
      }
    }
  }

  if (version) return { kind: 'version' };
  if (help) return commandGiven ? { kind: 'help', helpFor: command } : { kind: 'help' };

  let ruleId: string | undefined;
  let root = '.';

  if (command === 'rules') {
    ruleId = positionals[0];
    if (positionals.length > 1) throw new UsageError(`unexpected argument: ${positionals[1]}`);
  } else {
    root = positionals[0] ?? '.';
    if (positionals.length > 1) throw new UsageError(`unexpected argument: ${positionals[1]}`);
  }

  return {
    kind: 'args',
    args: {
      command,
      root,
      ...(ruleId !== undefined ? { ruleId } : {}),
      format,
      ...(failOn !== undefined ? { failOn } : {}),
      verbose,
      quiet,
      ...(includePossibleAgents !== undefined ? { includePossibleAgents } : {}),
    },
  };
}

function readSeverity(value: string | undefined): Severity {
  if (value !== undefined && (SEVERITIES as readonly string[]).includes(value)) return value as Severity;
  throw new UsageError(
    `--fail-on expects one of ${SEVERITIES.join(', ')}${value ? `, got "${value}"` : ''}`,
  );
}
