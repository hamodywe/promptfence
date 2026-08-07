/**
 * The human-facing report.
 *
 * Organised by workflow, because that is the file someone will open to fix it,
 * and every finding leads with what an attacker could do rather than with which
 * rule fired. A rule id tells a reader the tool has an opinion; a consequence
 * tells them whether to care.
 *
 * Jobs that run an agent but produced no findings are still listed, quietly.
 * "This agent has no untrusted input today and holds `contents: write`" is worth
 * seeing before somebody changes the trigger.
 */

import {
  type Finding,
  type JobAnalysis,
  type ScanReport,
  type Severity,
  type WorkflowAnalysis,
} from '../types.ts';
import { createStyler, padEnd, truncate, type StyleName, type Styler } from './style.ts';

export interface TerminalOptions {
  readonly verbose?: boolean;
  readonly quiet?: boolean;
  readonly warnings?: readonly string[];
}

const SEVERITY_COLOUR: Readonly<Record<Severity, StyleName>> = {
  critical: 'red',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
  info: 'grey',
};

export function renderTerminal(
  report: ScanReport,
  stream: NodeJS.WriteStream,
  options: TerminalOptions = {},
): string {
  const style = createStyler(stream);
  const lines: string[] = [];

  lines.push(
    `${style('bold', report.tool.name)} ${style('dim', report.tool.version)} ${style('dim', '·')} ${report.root}`,
  );
  lines.push('');

  for (const warning of options.warnings ?? []) {
    lines.push(`${style('yellow', 'warning')} ${warning}`);
  }
  if ((options.warnings ?? []).length > 0) lines.push('');

  const { summary } = report;
  lines.push(
    `${style('bold', String(summary.workflows))} workflows ${style('dim', '·')} ` +
      `${style('bold', String(summary.jobs))} jobs ${style('dim', '·')} ` +
      `${style('bold', String(summary.agentJobs))} run an AI agent`,
  );
  lines.push('');

  if (summary.agentJobs === 0) {
    lines.push(style('green', 'No AI agent steps found. There is nothing here for this tool to analyse.'));
    lines.push(
      style('dim', 'promptfence only reports on jobs that run a model — workflow security in general is'),
    );
    lines.push(style('dim', 'zizmor and actionlint territory.'));
    lines.push('');
    return lines.join('\n');
  }

  for (const workflow of report.workflows) {
    if (workflow.findings.length === 0 && !workflow.unanalysable) {
      if (options.verbose) lines.push(...renderQuietWorkflow(workflow, style));
      continue;
    }
    lines.push(...renderWorkflow(workflow, style, options));
  }

  lines.push(...renderSummary(report, style));
  lines.push('');

  return lines.join('\n');
}

function renderWorkflow(
  workflow: WorkflowAnalysis,
  style: Styler,
  options: TerminalOptions,
): string[] {
  const lines: string[] = [];

  lines.push(style('bold', workflow.path) + (workflow.name ? style('dim', ` — ${workflow.name}`) : ''));

  if (workflow.unanalysable) {
    lines.push(`  ${style('magenta', 'could not be parsed')} — this workflow was not analysed`);
    for (const error of workflow.errors.slice(0, 3)) {
      lines.push(`    ${style('grey', `line ${error.line}:`)} ${error.message}`);
    }
    lines.push('');
    return lines;
  }

  const agentJobs = workflow.jobs.filter((job) => job.agents.length > 0);
  if (agentJobs.length > 0) {
    lines.push(
      style(
        'dim',
        `  agents in: ${agentJobs.map((job) => job.jobId).join(', ')}  ·  triggers: ${workflow.triggers
          .map((trigger) => (trigger.privileged ? `${trigger.event}*` : trigger.event))
          .join(', ')}`,
      ),
    );
  }
  lines.push('');

  for (const finding of workflow.findings) {
    lines.push(...renderFinding(finding, style, options));
  }

  return lines;
}

function renderFinding(finding: Finding, style: Styler, options: TerminalOptions): string[] {
  const lines: string[] = [];

  lines.push(
    `  ${style(SEVERITY_COLOUR[finding.severity], padEnd(finding.severity, 8))} ` +
      `${style('cyan', finding.ruleId)} ${style('grey', `${finding.workflow}:${finding.line}`)}`,
  );
  lines.push(`    ${finding.message}`);
  lines.push(`    ${style('dim', 'so:')} ${finding.consequence}`);
  lines.push(`    ${style('dim', 'fix:')} ${finding.remediation}`);

  if (!options.quiet) {
    for (const evidence of finding.evidence) {
      const where = evidence.line !== undefined ? style('grey', ` (line ${evidence.line})`) : '';
      lines.push(`      ${style('dim', `${evidence.label}:`)} ${truncate(evidence.detail, 110)}${where}`);
    }
  }

  lines.push('');
  return lines;
}

function renderQuietWorkflow(workflow: WorkflowAnalysis, style: Styler): string[] {
  const agentJobs = workflow.jobs.filter((job) => job.agents.length > 0);
  if (agentJobs.length === 0) return [];

  const lines: string[] = [style('bold', workflow.path)];
  for (const job of agentJobs) lines.push(...renderJobPosture(job, style));
  lines.push('');
  return lines;
}

function renderJobPosture(job: JobAnalysis, style: Styler): string[] {
  const agent = job.agents[0];
  const capability = job.blast.permissionsUnset
    ? 'permissions unset'
    : job.blast.writeScopes.length > 0
      ? `write: ${job.blast.writeScopes.join(', ')}`
      : 'no write scopes';

  return [
    `  ${style('green', 'clean')}    ${job.jobId} ${style('dim', `— ${agent?.product ?? 'agent'}, ${capability}`)}`,
  ];
}

function renderSummary(report: ScanReport, style: Styler): string[] {
  const { summary } = report;
  const lines = [style('bold', 'Summary')];

  const severities = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((severity) => summary.bySeverity[severity] > 0)
    .map((severity) => `${style(SEVERITY_COLOUR[severity], severity)} ${summary.bySeverity[severity]}`)
    .join(style('dim', ' · '));

  lines.push(`  ${severities.length > 0 ? severities : style('green', 'no findings')}`);

  if (summary.unanalysable > 0) {
    lines.push(
      `  ${style('magenta', `${summary.unanalysable} workflow(s) could not be parsed and were not analysed`)}`,
    );
  }

  lines.push('');
  lines.push(style('dim', '  A trigger marked * runs with repository secrets and a write token while its'));
  lines.push(style('dim', '  content is written by outsiders. That is what turns injection into takeover.'));

  return lines;
}
