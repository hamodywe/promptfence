/**
 * SARIF 2.1.0, so findings land in GitHub code scanning.
 *
 * The value is not the format. It is that a finding becomes an alert with a
 * lifecycle: it appears on the pull request that introduced it, it can be
 * dismissed with a stated reason, and it closes itself when fixed. That is the
 * difference between a check people act on and one that scrolls past in a log.
 *
 * Results are anchored to the workflow file and line, which is exactly the file
 * a reviewer needs to edit — unusually convenient, since the subject of the
 * analysis is committed source rather than something downloaded at build time.
 */

import { RULES } from '../rules/catalog.ts';
import type { Finding, ScanReport, Severity } from '../types.ts';

const SARIF_LEVEL: Readonly<Record<Severity, 'error' | 'warning' | 'note'>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

/** GitHub sorts alerts by this. SARIF defines the range as 0.0–10.0. */
const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '3.0',
  info: '1.0',
};

export function renderSarif(report: ScanReport): string {
  const results = report.workflows.flatMap((workflow) =>
    workflow.findings.map((finding) => toResult(finding)),
  );

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            version: report.tool.version,
            semanticVersion: report.tool.version,
            informationUri: 'https://github.com/hamodywe/promptfence',
            rules: RULES.map((rule) => ({
              id: rule.id,
              name: toPascalCase(rule.id),
              shortDescription: { text: rule.title },
              fullDescription: { text: `${rule.summary} ${rule.rationale}` },
              help: { text: rule.remediation, markdown: rule.remediation },
              defaultConfiguration: { level: SARIF_LEVEL[rule.defaultSeverity] },
              properties: {
                tags: ['security', 'ci-cd', 'prompt-injection', 'ai-agents'],
                'security-severity': SECURITY_SEVERITY[rule.defaultSeverity],
              },
            })),
          },
        },
        results,
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function toResult(finding: Finding): unknown {
  return {
    ruleId: finding.ruleId,
    level: SARIF_LEVEL[finding.severity],
    message: {
      text: `${finding.message} ${finding.consequence} ${finding.remediation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.workflow },
          region: { startLine: Math.max(1, finding.line) },
        },
      },
    ],
    properties: {
      'security-severity': SECURITY_SEVERITY[finding.severity],
      severity: finding.severity,
      job: finding.jobId,
    },
    // Keeps an alert stable across runs so GitHub can tell "still open" from
    // "new" even when line numbers shift.
    partialFingerprints: {
      promptfence: `${finding.ruleId}:${finding.workflow}:${finding.jobId}`,
    },
  };
}

function toPascalCase(id: string): string {
  return id
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}
