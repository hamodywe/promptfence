/**
 * Fixture helpers.
 *
 * Workflows are written inline as YAML strings rather than as files, because
 * the thing under test is nearly always a two-line difference — a permissions
 * block, a trigger, one interpolation — and a test that shows the whole
 * workflow beside the assertion is a test whose failure explains itself.
 */

import { analyseWorkflow } from '../src/rules/evaluate.ts';
import { parseWorkflow } from '../src/workflow/model.ts';
import type { Finding, Severity, WorkflowAnalysis } from '../src/types.ts';

/** Parse and analyse a workflow given as YAML. */
export function analyse(yaml: string, path = '.github/workflows/test.yml'): WorkflowAnalysis {
  return analyseWorkflow(parseWorkflow(yaml, path));
}

/** The rule ids a workflow produced, sorted, for compact assertions. */
export function ruleIds(analysis: WorkflowAnalysis): string[] {
  return analysis.findings.map((finding) => finding.ruleId).sort();
}

/** Find one finding by rule id. */
export function findingFor(analysis: WorkflowAnalysis, ruleId: string): Finding | undefined {
  return analysis.findings.find((finding) => finding.ruleId === ruleId);
}

export function severityOf(analysis: WorkflowAnalysis, ruleId: string): Severity | undefined {
  return findingFor(analysis, ruleId)?.severity;
}

/**
 * A workflow with one agent step, parameterised over the parts that matter.
 *
 * Everything the tests vary is a knob here, so a case reads as "the same
 * workflow, but on `issue_comment`" rather than as another forty lines of YAML.
 */
export function workflow(options: {
  on?: string;
  permissions?: string;
  jobPermissions?: string;
  runsOn?: string;
  steps?: string;
}): string {
  const {
    on = 'workflow_dispatch',
    permissions,
    jobPermissions,
    runsOn = 'ubuntu-latest',
    steps = `      - uses: anthropics/claude-code-action@v1
        with:
          prompt: 'Do the thing'`,
  } = options;

  return [
    'name: Test',
    '',
    'on:',
    `  ${on}:`,
    '',
    ...(permissions !== undefined ? [`permissions: ${permissions}`, ''] : []),
    'jobs:',
    '  agent:',
    `    runs-on: ${runsOn}`,
    ...(jobPermissions !== undefined ? [`    permissions: ${jobPermissions}`] : []),
    '    steps:',
    steps,
    '',
  ].join('\n');
}

/** A write stream stand-in that captures output and never enables colour. */
export function captureStream(): NodeJS.WriteStream & { readonly text: string } {
  const chunks: string[] = [];
  const stream = {
    isTTY: false,
    write(chunk: string): boolean {
      chunks.push(chunk);
      return true;
    },
    get text(): string {
      return chunks.join('');
    },
  };
  return stream as unknown as NodeJS.WriteStream & { readonly text: string };
}
