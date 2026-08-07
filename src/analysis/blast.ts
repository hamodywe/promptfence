/**
 * What a hijacked agent could actually do.
 *
 * Prompt injection is not interesting on its own. An agent that has been talked
 * into writing a rude limerick has cost nobody anything. The question worth
 * asking is what the *job* is holding while the agent runs inside it: which
 * write scopes, which secrets, whether it can mint credentials for other
 * systems, whose code it checked out, and whose machine it is on.
 *
 * That is the blast radius, and it is what turns a curiosity into an incident.
 * It is computed independently of whether an injection path exists, so the
 * report can say "this agent has no untrusted input today, and if that changes
 * it can push to main" — which is a useful thing to know before the change.
 */

import { asMap, asString, asStringArray, type YamlMap, type YamlValue } from '../yaml/parse.ts';
import { flattenText, stepText, type Job, type Workflow } from '../workflow/model.ts';
import { isModelKeyName } from './agents.ts';
import type { BlastRadius } from '../types.ts';

/** Every scope `permissions:` can grant, for expanding `write-all`. */
const ALL_SCOPES = [
  'actions',
  'attestations',
  'checks',
  'contents',
  'deployments',
  'discussions',
  'id-token',
  'issues',
  'packages',
  'pages',
  'pull-requests',
  'repository-projects',
  'security-events',
  'statuses',
] as const;

/**
 * Scopes whose abuse is not recoverable by deleting a comment.
 *
 * `contents: write` lets an attacker push code, which on a repository with
 * publishing workflows means shipping it. `actions: write` lets them rewrite
 * the workflows that would have caught them. `packages: write` publishes.
 * `id-token: write` mints an OIDC token for whatever cloud account trusts this
 * repository, which is frequently the largest thing in reach.
 */
const CRITICAL_SCOPES = new Set(['contents', 'actions', 'packages', 'id-token', 'attestations', 'deployments']);

export interface PermissionResolution {
  readonly writeScopes: readonly string[];
  /** True when neither the job nor the workflow sets `permissions`. */
  readonly unset: boolean;
}

/**
 * Resolve the permissions in force for a job.
 *
 * A job's block replaces the workflow's outright — it does not merge, which is
 * a detail worth getting right, because a workflow-level `permissions: {}`
 * followed by a job-level `permissions: { issues: write }` grants issues and
 * nothing else, not issues plus whatever the default was.
 *
 * When neither sets anything, the answer depends on a repository setting this
 * tool cannot see. That is reported as `unset` rather than assumed either way:
 * on repositories created before February 2023, or with the setting left alone,
 * the default is still write access to almost everything.
 */
export function resolvePermissions(workflow: Workflow, job: Job): PermissionResolution {
  const applicable = job.permissions ?? workflow.permissions;
  if (applicable === null || applicable === undefined) return { writeScopes: [], unset: true };

  const shorthand = asString(applicable);
  if (shorthand === 'write-all') return { writeScopes: [...ALL_SCOPES], unset: false };
  if (shorthand === 'read-all' || shorthand === 'none') return { writeScopes: [], unset: false };

  const map = asMap(applicable);
  if (map === null) return { writeScopes: [], unset: false };

  const writes: string[] = [];
  for (const [scope, value] of Object.entries(map)) {
    if (asString(value) === 'write') writes.push(scope);
  }

  return { writeScopes: writes.sort(), unset: false };
}

/** Every `secrets.NAME` referenced anywhere in a job, plus the workflow-level ones. */
export function secretsInScope(workflow: Workflow, job: Job): string[] {
  const found = new Set<string>();

  const collect = (text: string): void => {
    const pattern = /secrets\.([A-Za-z_][A-Za-z0-9_]*)/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const name = match[1];
      // GITHUB_TOKEN is not a secret the workflow author chose to expose; its
      // power is described entirely by `permissions`, which is modelled above.
      if (name !== undefined && name !== 'GITHUB_TOKEN') found.add(name);
    }
  };

  for (const text of flattenText(workflow.env, 'env').values()) collect(text);
  for (const text of flattenText(job.env, `${job.path}.env`).values()) collect(text);
  for (const step of job.steps) {
    for (const text of stepText(step).values()) collect(text);
  }

  for (const name of job.secretsPassed) if (name !== 'GITHUB_TOKEN') found.add(name);
  if (job.secretsInherit) found.add('*inherit*');

  return [...found].sort();
}

/**
 * Whether the job checks out code an outsider can change.
 *
 * The dangerous shape is a privileged trigger combined with an explicit
 * checkout of the pull request head: the job then holds secrets *and* the
 * contributor's code, and the injection no longer even needs to go through the
 * model — a modified build script would do. With an agent in the job it is
 * worse, because the agent will read that code as part of its task.
 */
export function checksOutUntrustedCode(job: Job): boolean {
  const UNTRUSTED_REFS =
    /github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\/[^\s'"]*\/(?:head|merge)|github\.event\.workflow_run\.head_(?:sha|branch)/;

  for (const step of job.steps) {
    if (step.uses === null || !/^actions\/checkout(@|$)/i.test(step.uses)) continue;

    const ref = readWithString(step.with, 'ref');
    const repository = readWithString(step.with, 'repository');

    if (ref !== null && UNTRUSTED_REFS.test(ref)) return true;
    if (repository !== null && /github\.event\.pull_request\.head\.repo\.full_name/.test(repository)) {
      return true;
    }
  }

  return false;
}

function readWithString(map: YamlMap | null, key: string): string | null {
  if (map === null) return null;
  const value: YamlValue | undefined = map[key];
  return asString(value);
}

export function runsSelfHosted(job: Job): boolean {
  return job.runsOn.some((label) => /^self-hosted$/i.test(label) || label.includes('${{'));
}

/**
 * Score the capability a job holds, 0–100.
 *
 * The weights are deliberately coarse. The number exists to order a list of
 * findings so the worst one is at the top, not to be precise about how much
 * worse `packages: write` is than `issues: write`.
 */
export function computeBlastRadius(workflow: Workflow, job: Job): BlastRadius {
  const permissions = resolvePermissions(workflow, job);
  const all = secretsInScope(workflow, job);

  // The model key is separated out and scored at zero. Every agent needs one,
  // so counting it would raise the blast radius of every agent workflow by the
  // same amount — which orders nothing and alarms everybody.
  const modelKeys = all.filter((name) => isModelKeyName(name));
  const secrets = all.filter((name) => !isModelKeyName(name));

  const untrustedCheckout = checksOutUntrustedCode(job);
  const selfHosted = runsSelfHosted(job);
  const oidc = permissions.writeScopes.includes('id-token');

  let score = 0;
  for (const scope of permissions.writeScopes) {
    score += CRITICAL_SCOPES.has(scope) ? 20 : 8;
  }
  // An unset block is not "no permissions" — it is "whatever the repository
  // default is", which for a large share of repositories is write to nearly
  // everything. Scoring it as zero would rate the least explicit workflow as
  // the safest.
  if (permissions.unset) score += 25;

  if (secrets.includes('*inherit*')) score += 25;
  else score += Math.min(20, secrets.length * 7);

  if (untrustedCheckout) score += 20;
  if (selfHosted) score += 15;

  return {
    writeScopes: permissions.writeScopes,
    permissionsUnset: permissions.unset,
    secrets,
    modelKeys,
    oidc,
    untrustedCheckout,
    selfHosted,
    score: Math.min(100, score),
  };
}

/** The scopes worth naming in a message, worst first. */
export function notableScopes(blast: BlastRadius): string[] {
  return [...blast.writeScopes].sort((a, b) => {
    const rank = (scope: string): number => (CRITICAL_SCOPES.has(scope) ? 0 : 1);
    return rank(a) - rank(b) || a.localeCompare(b);
  });
}

/** Convenience for reporters that need the raw list of every scope. */
export { ALL_SCOPES, CRITICAL_SCOPES };

/** Read a `permissions` value straight from a YAML node, for tests. */
export function permissionsFrom(value: YamlValue | null): PermissionResolution {
  return resolvePermissions(
    { permissions: value } as unknown as Workflow,
    { permissions: null } as unknown as Job,
  );
}

/** Names referenced by a `with:` block, used by the rules for tool grants. */
export function withStrings(map: YamlMap | null, prefix: string): string[] {
  return [...flattenText(map, prefix).values()];
}

/** Split a comma or whitespace separated list, as action inputs tend to be. */
export function listValues(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter((item) => item !== '');
}

/** Read a string array or delimited string from an action input. */
export function readList(map: YamlMap | null, key: string): string[] {
  if (map === null) return [];
  const value = map[key];
  const asText = asString(value);
  if (asText !== null) return listValues(asText);
  return asStringArray(value);
}
