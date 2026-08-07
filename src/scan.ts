/**
 * The scan: one function that turns a directory into a report.
 *
 * Everything the CLI prints is a rendering of this, and the library export is
 * the same call, so the two cannot drift apart.
 */

import path from 'node:path';
import { isExcluded, loadConfig, type Config } from './config.ts';
import { analyseWorkflow } from './rules/evaluate.ts';
import { discoverWorkflows } from './workflow/discover.ts';
import { parseWorkflow } from './workflow/model.ts';
import {
  SEVERITIES,
  type ScanReport,
  type ScanSummary,
  type Severity,
  type WorkflowAnalysis,
} from './types.ts';

export const VERSION = '0.1.0';

export interface ScanOptions {
  /** A repository root, a workflows directory, or a single workflow file. */
  readonly root: string;
  /** Overrides `includePossibleAgents` from configuration. */
  readonly includePossibleAgents?: boolean;
}

export interface ScanResult {
  readonly report: ScanReport;
  readonly config: Config;
  readonly warnings: readonly string[];
  /** False when the target held no workflows at all. */
  readonly found: boolean;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const discovery = await discoverWorkflows(options.root);

  const loaded = await loadConfig(discovery.root);
  const config: Config = {
    ...loaded.config,
    ...(options.includePossibleAgents !== undefined
      ? { includePossibleAgents: options.includePossibleAgents }
      : {}),
  };

  const warnings = [...loaded.warnings];
  if (discovery.emptyReason !== undefined) warnings.push(discovery.emptyReason);

  const workflows: WorkflowAnalysis[] = [];

  for (const file of discovery.files) {
    if (isExcluded(config, file.path)) continue;

    const analysis = analyseWorkflow(parseWorkflow(file.source, file.path));
    workflows.push(applyConfig(analysis, config));
  }

  // Worst workflow first, then alphabetical, so a long report opens on the
  // thing worth reading.
  workflows.sort((a, b) => worstSeverity(a) - worstSeverity(b) || a.path.localeCompare(b.path));

  return {
    report: {
      schemaVersion: 1,
      tool: { name: 'promptfence', version: VERSION },
      root: path.resolve(discovery.root),
      summary: summarise(workflows),
      workflows,
    },
    config,
    warnings,
    found: discovery.files.length > 0,
  };
}

/**
 * Apply the suppressions.
 *
 * Disabled rules are dropped, and — when `includePossibleAgents` is off — so is
 * every finding whose only agent evidence was a model API key in scope. The
 * jobs stay in the report either way, because "this job runs an agent with
 * `contents: write` and we chose not to report on it" is still worth being able
 * to see.
 */
function applyConfig(analysis: WorkflowAnalysis, config: Config): WorkflowAnalysis {
  const jobs = config.includePossibleAgents
    ? analysis.jobs
    : analysis.jobs.map((job) => ({
        ...job,
        agents: job.agents.filter((agent) => agent.confidence !== 'possible'),
      }));

  const jobsWithAgents = new Set(jobs.filter((job) => job.agents.length > 0).map((job) => job.jobId));

  const findings = analysis.findings.filter(
    (finding) => !config.disable.includes(finding.ruleId) && jobsWithAgents.has(finding.jobId),
  );

  return { ...analysis, jobs, findings };
}

function worstSeverity(analysis: WorkflowAnalysis): number {
  let worst: number = SEVERITIES.length;
  for (const finding of analysis.findings) {
    worst = Math.min(worst, SEVERITIES.indexOf(finding.severity));
  }
  return worst;
}

function summarise(workflows: readonly WorkflowAnalysis[]): ScanSummary {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;

  let jobs = 0;
  let agentJobs = 0;
  let findings = 0;
  let unanalysable = 0;

  for (const workflow of workflows) {
    if (workflow.unanalysable) unanalysable += 1;
    jobs += workflow.jobs.length;
    agentJobs += workflow.jobs.filter((job) => job.agents.length > 0).length;
    findings += workflow.findings.length;

    for (const finding of workflow.findings) bySeverity[finding.severity] += 1;
  }

  return { workflows: workflows.length, unanalysable, jobs, agentJobs, findings, bySeverity };
}

/** Every finding across the report, worst first. */
export function allFindings(report: ScanReport) {
  return report.workflows
    .flatMap((workflow) => workflow.findings)
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
}
