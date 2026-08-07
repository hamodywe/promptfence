/**
 * The workflow model.
 *
 * Only what bears on the question is modelled: where outsider-controlled text
 * can enter, where an agent reads its instructions, and what the surrounding
 * job is permitted to do. There is no attempt at a complete representation of
 * workflow syntax — `actionlint` validates schemas thoroughly and this tool does
 * not duplicate it.
 *
 * Every node carries two things the analysis cannot work without: the line it
 * came from, so a finding can point at `line 34` rather than at a file, and its
 * dotted path, so a report can say *where* — `jobs.review.steps[2].with.prompt`
 * — rather than leaving a reader to search for it.
 */

import {
  asArray,
  asMap,
  asString,
  asStringArray,
  isMap,
  parseYaml,
  type YamlError,
  type YamlMap,
  type YamlValue,
} from '../yaml/parse.ts';

export interface Step {
  readonly name: string | null;
  /** The action reference, e.g. `actions/checkout@v4`. */
  readonly uses: string | null;
  /** The shell script body. */
  readonly run: string | null;
  readonly with: YamlMap | null;
  readonly env: YamlMap | null;
  readonly if: string | null;
  /** Dotted path, e.g. `jobs.review.steps[2]`. */
  readonly path: string;
  readonly line: number;
}

export interface Job {
  readonly id: string;
  readonly name: string | null;
  readonly runsOn: readonly string[];
  /**
   * Raw `permissions` for this job. `null` means the key is absent, which is
   * not the same as an empty block — absent inherits, empty grants nothing.
   */
  readonly permissions: YamlValue | null;
  readonly env: YamlMap | null;
  readonly steps: readonly Step[];
  readonly if: string | null;
  /** A reusable workflow reference, when this job calls one. */
  readonly usesWorkflow: string | null;
  /** True when the job passes `secrets: inherit` to a called workflow. */
  readonly secretsInherit: boolean;
  /** Secret names passed explicitly to a called workflow. */
  readonly secretsPassed: readonly string[];
  readonly path: string;
  readonly line: number;
}

export interface Trigger {
  readonly event: string;
  readonly types: readonly string[];
  readonly branches: readonly string[];
  readonly line: number;
}

export interface Workflow {
  /** Path as given, POSIX-separated and relative to the scan root. */
  readonly path: string;
  readonly name: string | null;
  readonly triggers: readonly Trigger[];
  readonly permissions: YamlValue | null;
  readonly env: YamlMap | null;
  readonly jobs: readonly Job[];
  readonly errors: readonly YamlError[];
  /** True when parsing failed badly enough that analysis would mislead. */
  readonly unanalysable: boolean;
  readonly lines: ReadonlyMap<string, number>;
  readonly source: string;
}

export function parseWorkflow(source: string, path: string): Workflow {
  const document = parseYaml(source);
  const root = asMap(document.value);

  const empty: Workflow = {
    path,
    name: null,
    triggers: [],
    permissions: null,
    env: null,
    jobs: [],
    errors: document.errors,
    unanalysable: true,
    lines: document.lines,
    source,
  };

  // A workflow that will not parse is reported as unanalysable rather than
  // analysed as empty. "No findings" and "could not look" must never render the
  // same way in a security tool.
  if (root === null) return empty;

  const lineOf = (dotted: string, fallback = 1): number => document.lines.get(dotted) ?? fallback;

  return {
    path,
    name: asString(root['name']),
    triggers: parseTriggers(root['on'] ?? root[true as unknown as string], lineOf),
    permissions: root['permissions'] ?? null,
    env: asMap(root['env']),
    jobs: parseJobs(asMap(root['jobs']), lineOf),
    errors: document.errors,
    unanalysable: false,
    lines: document.lines,
    source,
  };
}

/**
 * `on:` is the one key in the schema that YAML itself fights.
 *
 * Unquoted `on` is a boolean in YAML 1.1, and while GitHub reads workflows as
 * YAML 1.2 — where it stays a string — enough tooling in the chain does not
 * that both spellings have to be handled. The parser here keeps `on` a string
 * key; the boolean lookup above is belt and braces.
 */
function parseTriggers(
  value: YamlValue | undefined,
  lineOf: (path: string, fallback?: number) => number,
): Trigger[] {
  if (value === undefined || value === null) return [];

  // `on: push`
  const single = asString(value);
  if (single !== null) {
    return [{ event: single, types: [], branches: [], line: lineOf('on') }];
  }

  // `on: [push, pull_request]`
  if (Array.isArray(value)) {
    return asStringArray(value).map((event) => ({
      event,
      types: [],
      branches: [],
      line: lineOf('on'),
    }));
  }

  const map = asMap(value);
  if (map === null) return [];

  const triggers: Trigger[] = [];
  for (const [event, config] of Object.entries(map)) {
    const detail = asMap(config);
    triggers.push({
      event,
      types: detail ? asStringArray(detail['types']) : [],
      branches: detail ? asStringArray(detail['branches']) : [],
      line: lineOf(`on.${event}`, lineOf('on')),
    });
  }
  return triggers;
}

function parseJobs(
  jobs: YamlMap | null,
  lineOf: (path: string, fallback?: number) => number,
): Job[] {
  if (jobs === null) return [];

  const parsed: Job[] = [];

  for (const [id, value] of Object.entries(jobs)) {
    const job = asMap(value);
    const jobPath = `jobs.${id}`;
    if (job === null) continue;

    const secrets = job['secrets'];
    const secretsInherit = asString(secrets) === 'inherit';
    const secretsMap = asMap(secrets);

    parsed.push({
      id,
      name: asString(job['name']),
      runsOn: parseRunsOn(job['runs-on']),
      permissions: job['permissions'] ?? null,
      env: asMap(job['env']),
      steps: parseSteps(job['steps'], jobPath, lineOf),
      if: asString(job['if']),
      usesWorkflow: asString(job['uses']),
      secretsInherit,
      secretsPassed: secretsMap ? Object.keys(secretsMap) : [],
      path: jobPath,
      line: lineOf(jobPath),
    });
  }

  return parsed;
}

function parseRunsOn(value: YamlValue | undefined): string[] {
  const single = asString(value);
  if (single !== null) return [single];
  if (Array.isArray(value)) return asStringArray(value);

  // `runs-on: { group: …, labels: [...] }`
  const map = asMap(value);
  if (map === null) return [];
  return [...asStringArray(map['labels']), ...(asString(map['group']) !== null ? [asString(map['group']) as string] : [])];
}

function parseSteps(
  value: YamlValue | undefined,
  jobPath: string,
  lineOf: (path: string, fallback?: number) => number,
): Step[] {
  const steps: Step[] = [];

  for (const [index, entry] of asArray(value).entries()) {
    if (!isMap(entry)) continue;
    const stepPath = `${jobPath}.steps[${index}]`;

    steps.push({
      name: asString(entry['name']),
      uses: asString(entry['uses']),
      run: asString(entry['run']),
      with: asMap(entry['with']),
      env: asMap(entry['env']),
      if: asString(entry['if']),
      path: stepPath,
      line: lineOf(stepPath, lineOf(jobPath)),
    });
  }

  return steps;
}

/**
 * Flatten a `with:` or `env:` block into `path -> text` pairs.
 *
 * Nested values are walked because agent actions take structured input —
 * `with.claude_args`, `with.prompt`, and lists of allowed tools — and a source
 * hiding two levels down is still a source.
 */
export function flattenText(
  map: YamlMap | null,
  prefix: string,
  out: Map<string, string> = new Map(),
): Map<string, string> {
  if (map === null) return out;

  for (const [key, value] of Object.entries(map)) {
    const path = `${prefix}.${key}`;
    if (typeof value === 'string') out.set(path, value);
    else if (isMap(value)) flattenText(value, path, out);
    else if (Array.isArray(value)) {
      for (const [index, item] of value.entries()) {
        if (typeof item === 'string') out.set(`${path}[${index}]`, item);
        else if (isMap(item)) flattenText(item, `${path}[${index}]`, out);
      }
    }
  }

  return out;
}

/** Every piece of text a step carries, keyed by dotted path. */
export function stepText(step: Step): Map<string, string> {
  const text = new Map<string, string>();
  if (step.run !== null) text.set(`${step.path}.run`, step.run);
  if (step.if !== null) text.set(`${step.path}.if`, step.if);
  flattenText(step.with, `${step.path}.with`, text);
  flattenText(step.env, `${step.path}.env`, text);
  return text;
}

/** Split an action reference into its repository part and its version. */
export function splitActionRef(uses: string): { action: string; ref: string | null } {
  const at = uses.lastIndexOf('@');
  if (at <= 0) return { action: uses, ref: null };
  return { action: uses.slice(0, at), ref: uses.slice(at + 1) };
}

/** True when a ref is a 40-character commit SHA rather than a moving tag. */
export function isPinnedToSha(ref: string | null): boolean {
  return ref !== null && /^[0-9a-f]{40}$/i.test(ref);
}
