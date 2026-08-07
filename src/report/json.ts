/**
 * The machine-readable report.
 *
 * `schemaVersion` is the contract. Anything that would break a consumer reading
 * this — removing a field, changing a type, changing what a value means —
 * increments it and is listed in the CHANGELOG. Adding a field does not, so
 * consumers should ignore keys they do not recognise.
 */

import type { ScanReport } from '../types.ts';

export interface JsonOptions {
  readonly warnings?: readonly string[];
  readonly pretty?: boolean;
}

export function renderJson(report: ScanReport, options: JsonOptions = {}): string {
  const payload = {
    schemaVersion: report.schemaVersion,
    tool: report.tool,
    summary: report.summary,
    warnings: options.warnings ?? [],
    workflows: report.workflows.map((workflow) => ({
      path: workflow.path,
      name: workflow.name,
      unanalysable: workflow.unanalysable,
      errors: workflow.errors,
      triggers: workflow.triggers.map((trigger) => ({
        event: trigger.event,
        privileged: trigger.privileged,
        line: trigger.line,
      })),
      jobs: workflow.jobs.map((job) => ({
        id: job.jobId,
        name: job.name,
        line: job.line,
        agents: job.agents.map((agent) => ({
          step: agent.stepIndex,
          name: agent.name,
          uses: agent.uses,
          product: agent.product,
          confidence: agent.confidence,
          evidence: agent.evidence,
          unpinned: agent.unpinned,
          line: agent.line,
        })),
        untrustedSources: job.sources.map((source) => ({
          kind: source.kind,
          expression: source.expression,
          control: source.control,
          path: source.path,
          line: source.line,
        })),
        blastRadius: {
          writeScopes: job.blast.writeScopes,
          permissionsUnset: job.blast.permissionsUnset,
          secrets: job.blast.secrets,
          oidc: job.blast.oidc,
          untrustedCheckout: job.blast.untrustedCheckout,
          selfHosted: job.blast.selfHosted,
          score: job.blast.score,
        },
      })),
      findings: workflow.findings.map((finding) => ({
        ruleId: finding.ruleId,
        severity: finding.severity,
        job: finding.jobId,
        line: finding.line,
        message: finding.message,
        consequence: finding.consequence,
        remediation: finding.remediation,
        evidence: finding.evidence,
      })),
    })),
  };

  return options.pretty === false ? JSON.stringify(payload) : `${JSON.stringify(payload, null, 2)}\n`;
}
