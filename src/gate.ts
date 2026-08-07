/**
 * The build gate.
 *
 * The verdict is returned with its reasons rather than as a boolean, because a
 * bare non-zero exit sends people to read the tool's source and then to disable
 * it. "Failed: 1 critical — a `pull_request_target` job checks out the
 * contributor's code and runs an agent" is a sentence someone can act on.
 */

import type { Config } from './config.ts';
import { allFindings } from './scan.ts';
import { isAtLeast, type Finding, type ScanReport, type Severity } from './types.ts';

export interface GateResult {
  readonly passed: boolean;
  readonly reasons: readonly string[];
  readonly failOn: Severity;
  /** Findings that met the threshold but are configured as warn-only. */
  readonly waived: readonly Finding[];
}

export interface GateOptions {
  readonly failOn?: Severity;
}

export function evaluateGate(report: ScanReport, config: Config, options: GateOptions = {}): GateResult {
  const failOn = options.failOn ?? config.failOn;

  const overThreshold = allFindings(report).filter((finding) => isAtLeast(finding.severity, failOn));
  const waived = overThreshold.filter((finding) => config.warnOnly.includes(finding.ruleId));
  const gating = overThreshold.filter((finding) => !config.warnOnly.includes(finding.ruleId));

  const reasons: string[] = [];

  // Group by rule so ten instances of one problem read as one problem.
  const byRule = new Map<string, Finding[]>();
  for (const finding of gating) {
    const existing = byRule.get(finding.ruleId);
    if (existing) existing.push(finding);
    else byRule.set(finding.ruleId, [finding]);
  }

  for (const [ruleId, findings] of byRule) {
    const first = findings[0] as Finding;
    const where =
      findings.length === 1
        ? `${first.workflow}:${first.line}`
        : `${findings.length} places, starting at ${first.workflow}:${first.line}`;
    reasons.push(`${first.severity} · ${ruleId} — ${where}`);
  }

  // A workflow that could not be parsed is not a pass. Reporting nothing and
  // reporting nothing found have to be distinguishable, and the gate is the one
  // place where confusing them is expensive.
  const unanalysable = report.workflows.filter((workflow) => workflow.unanalysable);
  if (unanalysable.length > 0) {
    reasons.push(
      `${unanalysable.length} workflow${unanalysable.length === 1 ? '' : 's'} could not be parsed and ${unanalysable.length === 1 ? 'was' : 'were'} not analysed: ${unanalysable
        .map((workflow) => workflow.path)
        .join(', ')}`,
    );
  }

  return { passed: reasons.length === 0, reasons, failOn, waived };
}
