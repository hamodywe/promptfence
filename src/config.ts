/**
 * Project configuration.
 *
 * Optional, and designed to stay that way. What it buys is the ability to
 * record a decision *with its reason*: a suppressed rule that carries a note is
 * something the next reader can evaluate, where a finding quietly missing from
 * a report is just a gap.
 *
 * JSON rather than a JavaScript module. A config file that can execute code is
 * a strange thing to ship with a tool whose subject is untrusted code execution
 * in CI.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { RULES } from './rules/catalog.ts';
import { SEVERITIES, type Severity } from './types.ts';

export const CONFIG_FILENAME = 'promptfence.config.json';

export interface Config {
  /** Severity at or above which `promptfence check` fails. */
  readonly failOn: Severity;
  /** Rule ids that are reported but never fail the gate. */
  readonly warnOnly: readonly string[];
  /** Rule ids suppressed entirely. */
  readonly disable: readonly string[];
  /** Workflow paths excluded, matched as a suffix of the reported path. */
  readonly exclude: readonly string[];
  /**
   * Whether a step is reported when the only evidence of an agent is a model
   * API key in scope. Off makes the report quieter and blind to any wrapper the
   * catalogue does not know about.
   */
  readonly includePossibleAgents: boolean;
}

export const DEFAULT_CONFIG: Config = {
  // `high` rather than `medium`: an unpinned action on a fork-triggered
  // workflow is worth knowing about and is not worth stopping a merge for. A
  // gate that fires on everything teaches people to bypass it.
  failOn: 'high',
  warnOnly: [],
  disable: [],
  exclude: [],
  includePossibleAgents: true,
};

export interface LoadedConfig {
  readonly config: Config;
  readonly file?: string;
  readonly warnings: readonly string[];
}

const KNOWN_RULES = new Set(RULES.map((rule) => rule.id));

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseConfig(text: string): { config: Config; warnings: string[] } {
  const warnings: string[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    warnings.push(`config is not valid JSON and was ignored: ${(error as Error).message}`);
    return { config: DEFAULT_CONFIG, warnings };
  }

  if (!isRecord(parsed)) {
    warnings.push('config must be a JSON object; using defaults');
    return { config: DEFAULT_CONFIG, warnings };
  }

  let failOn = DEFAULT_CONFIG.failOn;
  const rawFailOn = parsed['failOn'];
  if (rawFailOn !== undefined) {
    if (typeof rawFailOn === 'string' && (SEVERITIES as readonly string[]).includes(rawFailOn)) {
      failOn = rawFailOn as Severity;
    } else {
      warnings.push(`"failOn" must be one of ${SEVERITIES.join(', ')}; using "${failOn}"`);
    }
  }

  return {
    config: {
      failOn,
      warnOnly: ruleList(parsed, 'warnOnly', warnings),
      disable: ruleList(parsed, 'disable', warnings),
      exclude: stringList(parsed, 'exclude', warnings),
      includePossibleAgents: boolean(
        parsed,
        'includePossibleAgents',
        DEFAULT_CONFIG.includePossibleAgents,
        warnings,
      ),
    },
    warnings,
  };
}

/**
 * Read a list of rule ids, complaining about ones that do not exist.
 *
 * A typo in `disable` silently suppresses nothing, which reads exactly like a
 * rule that never fires — and a security tool that appears to be checking
 * something it is not is worse than one that is honestly switched off.
 */
function ruleList(source: Record<string, unknown>, key: string, warnings: string[]): string[] {
  const values = stringList(source, key, warnings);
  const kept: string[] = [];

  for (const value of values) {
    if (KNOWN_RULES.has(value)) kept.push(value);
    else warnings.push(`"${key}" names an unknown rule: ${value}`);
  }

  return kept;
}

function stringList(source: Record<string, unknown>, key: string, warnings: string[]): string[] {
  const value = source[key];
  if (value === undefined) return [];

  if (!Array.isArray(value)) {
    warnings.push(`"${key}" must be an array of strings; using an empty list`);
    return [];
  }

  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string' && item.trim() !== '') out.push(item.trim());
    else warnings.push(`"${key}" entries must be non-empty strings; skipped one`);
  }
  return out;
}

function boolean(
  source: Record<string, unknown>,
  key: string,
  fallback: boolean,
  warnings: string[],
): boolean {
  const value = source[key];
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  warnings.push(`"${key}" must be true or false; using ${fallback}`);
  return fallback;
}

export async function loadConfig(root: string): Promise<LoadedConfig> {
  const file = path.join(root, CONFIG_FILENAME);

  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    return { config: DEFAULT_CONFIG, warnings: [] };
  }

  const { config, warnings } = parseConfig(text);
  return { config, file, warnings };
}

/** Whether a workflow path is excluded. Matched as a suffix, so both forms work. */
export function isExcluded(config: Config, workflowPath: string): boolean {
  return config.exclude.some(
    (pattern) => workflowPath === pattern || workflowPath.endsWith(`/${pattern}`),
  );
}
