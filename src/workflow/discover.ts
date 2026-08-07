/**
 * Finding the workflows.
 *
 * Three inputs have to work, because all three are what people type: a
 * repository root, a `.github/workflows` directory, and a single file. The
 * first is the common case and the other two are what someone reaches for when
 * they are iterating on one workflow.
 *
 * Composite actions are read too when they sit in the repository, because
 * `uses: ./.github/actions/review` is where a workflow's real steps often live,
 * and analysing the caller while ignoring the callee reports a job as empty.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const WORKFLOW_EXTENSIONS = new Set(['.yml', '.yaml']);

export interface WorkflowFile {
  /** Absolute path on disk. */
  readonly absolute: string;
  /** Path relative to the scan root, POSIX-separated. */
  readonly path: string;
  readonly source: string;
}

export interface DiscoveryResult {
  readonly files: readonly WorkflowFile[];
  /** The directory paths were resolved against. */
  readonly root: string;
  /** Set when the target existed but held no workflows. */
  readonly emptyReason?: string;
}

export async function discoverWorkflows(target: string): Promise<DiscoveryResult> {
  const resolved = path.resolve(target);
  const info = await stat(resolved).catch(() => undefined);

  if (info === undefined) {
    throw new Error(`no such file or directory: ${target}`);
  }

  if (info.isFile()) {
    const root = path.dirname(resolved);
    return {
      root,
      files: [
        {
          absolute: resolved,
          path: toPosix(path.basename(resolved)),
          source: await readFile(resolved, 'utf8'),
        },
      ],
    };
  }

  // A repository root, or the workflows directory itself.
  const candidates = [path.join(resolved, '.github', 'workflows'), resolved];

  for (const directory of candidates) {
    const files = await collect(directory, resolved);
    if (files.length > 0) return { root: resolved, files };
  }

  return {
    root: resolved,
    files: [],
    emptyReason: `no .yml or .yaml workflows under ${toPosix(path.relative(process.cwd(), resolved) || '.')}`,
  };
}

async function collect(directory: string, root: string): Promise<WorkflowFile[]> {
  let entries: string[];
  try {
    entries = (await readdir(directory)).sort();
  } catch {
    return [];
  }

  const files: WorkflowFile[] = [];

  for (const entry of entries) {
    if (!WORKFLOW_EXTENSIONS.has(path.extname(entry).toLowerCase())) continue;

    const absolute = path.join(directory, entry);
    const info = await stat(absolute).catch(() => undefined);
    if (info === undefined || !info.isFile()) continue;

    files.push({
      absolute,
      path: toPosix(path.relative(root, absolute)),
      source: await readFile(absolute, 'utf8'),
    });
  }

  return files;
}

function toPosix(value: string): string {
  return value.replace(/\\/g, '/');
}
