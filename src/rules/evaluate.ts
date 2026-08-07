/**
 * Joining source, sink and blast radius into findings.
 *
 * The rules themselves are simple. What takes care is severity, because the
 * same construction means very different things depending on the trigger:
 *
 *  - `${{ github.event.issue.body }}` in an agent prompt under `issue_comment`
 *    hands an attacker the repository's secrets and write token. Critical.
 *  - The identical line under a fork's `pull_request` hands them a read-only
 *    token and no secrets. Worth fixing, not worth waking anyone.
 *
 * A tool that scores both the same is wrong twice: it cries wolf on the second
 * and, by doing so, teaches people to scroll past the first.
 */

import { computeBlastRadius, notableScopes } from '../analysis/blast.ts';
import { detectAgents, type AgentDetection } from '../analysis/agents.ts';
import {
  carriesUntrustedContent,
  fetchCommandsIn,
  isPrivilegedTrigger,
  untrustedReferencesIn,
} from '../analysis/contexts.ts';
import { flattenText, stepText, type Job, type Workflow } from '../workflow/model.ts';
import { defaultSeverityOf } from './catalog.ts';
import {
  compareSeverity,
  SEVERITIES,
  type BlastRadius,
  type Evidence,
  type Finding,
  type JobAnalysis,
  type Severity,
  type TriggerFacts,
  type UntrustedSource,
  type WorkflowAnalysis,
} from '../types.ts';

export function analyseWorkflow(workflow: Workflow): WorkflowAnalysis {
  const triggers: TriggerFacts[] = workflow.triggers.map((trigger) => ({
    event: trigger.event,
    privileged: isPrivilegedTrigger(trigger.event),
    line: trigger.line,
  }));

  if (workflow.unanalysable) {
    return {
      path: workflow.path,
      name: workflow.name,
      triggers,
      jobs: [],
      findings: [],
      errors: workflow.errors.map((error) => ({ line: error.line, message: error.message })),
      unanalysable: true,
    };
  }

  const jobs: JobAnalysis[] = [];
  const findings: Finding[] = [];

  for (const job of workflow.jobs) {
    const analysis = analyseJob(workflow, job, triggers);
    jobs.push(analysis);
    findings.push(...evaluateJob(workflow, job, analysis));
  }

  findings.sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.line - b.line || a.ruleId.localeCompare(b.ruleId),
  );

  return {
    path: workflow.path,
    name: workflow.name,
    triggers,
    jobs,
    findings,
    errors: workflow.errors.map((error) => ({ line: error.line, message: error.message })),
    unanalysable: false,
  };
}

function analyseJob(workflow: Workflow, job: Job, triggers: readonly TriggerFacts[]): JobAnalysis {
  const agents = detectAgents(job.id, job.steps);
  const blast = computeBlastRadius(workflow, job);

  const sources: UntrustedSource[] = [];

  // Direct: an outsider-controlled context appears in the job's own text.
  const texts = new Map<string, { text: string; line: number }>();
  for (const [path, text] of flattenText(job.env, `${job.path}.env`)) {
    texts.set(path, { text, line: job.line });
  }
  for (const step of job.steps) {
    for (const [path, text] of stepText(step)) texts.set(path, { text, line: step.line });
  }

  for (const [path, { text, line }] of texts) {
    for (const match of untrustedReferencesIn(text)) {
      sources.push({
        kind: 'direct',
        expression: match.expression,
        control: match.control,
        path,
        line,
      });
    }
    for (const match of fetchCommandsIn(text)) {
      sources.push({
        kind: 'indirect',
        expression: match.expression,
        control: match.control,
        path,
        line,
      });
    }
  }

  return {
    jobId: job.id,
    name: job.name,
    line: job.line,
    agents,
    sources,
    blast,
    triggers,
  };
}

/** Highest privilege among the workflow's triggers. */
function triggerPosture(triggers: readonly TriggerFacts[]): {
  privileged: boolean;
  untrusted: boolean;
  names: string[];
} {
  const privileged = triggers.filter((trigger) => trigger.privileged);
  const untrusted = triggers.filter((trigger) => carriesUntrustedContent(trigger.event));

  return {
    privileged: privileged.length > 0,
    untrusted: untrusted.length > 0,
    names: (privileged.length > 0 ? privileged : untrusted).map((trigger) => trigger.event),
  };
}

function evaluateJob(workflow: Workflow, job: Job, analysis: JobAnalysis): Finding[] {
  const findings: Finding[] = [];
  const { agents, sources, blast } = analysis;

  // Every rule here is about agents. A workflow with no agent step is not this
  // tool's business, and reporting on it would be duplicating zizmor.
  if (agents.length === 0) return findings;

  const posture = triggerPosture(analysis.triggers);
  const agent = agents[0] as AgentDetection;
  /**
   * Whether outsider text can reach this agent today.
   *
   * Capability findings are raised only when it can *and* the trigger is
   * privileged. An agent with `contents: write` on a scheduled job is a
   * standing risk worth noting at medium; the same agent reachable from an
   * issue comment is a live one.
   */
  const reachable = hasInjectionPath(analysis, agent, posture);
  const emit = (finding: Omit<Finding, 'workflow' | 'jobId'>): void => {
    findings.push({ ...finding, workflow: workflow.path, jobId: job.id });
  };

  const blastEvidence = describeBlast(blast);
  const agentEvidence: Evidence = {
    label: 'agent',
    detail: `${agent.product ?? 'an AI agent'} — ${agent.evidence} (${agent.confidence})`,
    line: agent.line,
  };

  // 1. Untrusted text interpolated into a step.
  const direct = sources.filter((source) => source.kind === 'direct');
  if (direct.length > 0) {
    emit({
      ruleId: 'agent-reads-interpolated-input',
      severity: escalate('agent-reads-interpolated-input', posture.privileged, blast, agent),
      line: direct[0]?.line ?? agent.line,
      message: `${describeAgent(agent)} in job "${job.id}" is given text written by outsiders: ${direct
        .slice(0, 3)
        .map((source) => `\`${source.expression}\``)
        .join(', ')}.`,
      consequence: consequenceFor(posture, blast),
      remediation:
        'Hand the text over through an environment variable, tell the agent to treat it as data, and keep permissions out of the job that reads it.',
      evidence: [
        agentEvidence,
        ...direct.slice(0, 4).map(
          (source): Evidence => ({
            label: source.path,
            detail: `${source.expression} — ${source.control}`,
            line: source.line,
          }),
        ),
        blastEvidence,
      ],
    });
  }

  // 2. The agent reads the event payload itself. No expression to find.
  if (agent.ingestsEvent && posture.untrusted) {
    emit({
      ruleId: 'agent-ingests-untrusted-event',
      severity: escalate('agent-ingests-untrusted-event', posture.privileged, blast, agent),
      line: agent.line,
      message: `${describeAgent(agent)} in job "${job.id}" reads the triggering event, and this workflow runs on ${posture.names.join(', ')} — whose content anyone can write.`,
      consequence: consequenceFor(posture, blast),
      remediation:
        'Gate the job on the author’s association with the repository, and reduce its permissions to what the task actually needs.',
      evidence: [
        agentEvidence,
        {
          label: 'trigger',
          detail: `${posture.names.join(', ')} — the payload is written by whoever opened the issue, comment or pull request`,
          line: analysis.triggers[0]?.line ?? 1,
        },
        blastEvidence,
      ],
    });
  }

  // 3. A step goes and fetches outsider text.
  const indirect = sources.filter((source) => source.kind === 'indirect');
  if (indirect.length > 0) {
    emit({
      ruleId: 'agent-fetches-untrusted-content',
      severity: escalate('agent-fetches-untrusted-content', posture.privileged, blast, agent),
      line: indirect[0]?.line ?? agent.line,
      message: `Job "${job.id}" fetches text that outsiders write (\`${indirect[0]?.expression}\`) and runs ${describeAgent(agent)}.`,
      consequence: consequenceFor(posture, blast),
      remediation:
        'Treat fetched text as untrusted where it is fetched, and keep the privileged work in a separate job.',
      evidence: [
        agentEvidence,
        ...indirect.slice(0, 3).map(
          (source): Evidence => ({ label: source.path, detail: source.control, line: source.line }),
        ),
        blastEvidence,
      ],
    });
  }

  // 4. Privileged trigger + outsider code + agent.
  if (blast.untrustedCheckout && posture.privileged) {
    emit({
      ruleId: 'untrusted-checkout-with-agent',
      severity: 'critical',
      line: agent.line,
      message: `Job "${job.id}" runs on ${posture.names.join(', ')}, checks out the contributor’s code, and runs ${describeAgent(agent)}.`,
      consequence:
        'The contributor controls the files the agent reads, and the job is holding the base repository’s secrets while it reads them. Instructions can be placed in any file the agent opens.',
      remediation:
        'Split the workflow: build the contributor’s code in an unprivileged job, and let a privileged job consume only the result.',
      evidence: [
        agentEvidence,
        { label: 'checkout', detail: 'checks out a ref an outsider controls', line: job.line },
        blastEvidence,
      ],
    });
  }

  // 5–10. Capability findings. These stand on their own: they describe what a
  // hijacked agent would hold, whether or not a path into it exists today.
  const critical = notableScopes(blast).filter((scope) =>
    ['contents', 'actions', 'packages', 'id-token', 'deployments', 'attestations'].includes(scope),
  );
  if (critical.length > 0) {
    emit({
      ruleId: 'agent-holds-write-permissions',
      severity: reachable && posture.privileged ? 'high' : 'medium',
      line: job.line,
      message: `Job "${job.id}" grants ${critical.map((scope) => `\`${scope}: write\``).join(', ')} to a job that runs ${describeAgent(agent)}.`,
      consequence: writeConsequence(critical),
      remediation: 'Reduce `permissions` on the job to the narrowest set the task needs.',
      evidence: [agentEvidence, blastEvidence],
    });
  }

  // The model provider key is excluded upstream: every agent needs one, so a
  // finding that included it would fire on every agent workflow ever written.
  const namedSecrets = blast.secrets.filter((name) => name !== '*inherit*');
  if (namedSecrets.length > 0) {
    emit({
      ruleId: 'agent-holds-secrets',
      severity: reachable && posture.privileged ? 'high' : 'medium',
      line: job.line,
      message: `${namedSecrets.length} secret${namedSecrets.length === 1 ? ' beyond GITHUB_TOKEN is' : 's beyond GITHUB_TOKEN are'} in scope where ${describeAgent(agent)} runs: ${namedSecrets
        .slice(0, 4)
        .map((name) => `\`${name}\``)
        .join(', ')}.`,
      consequence:
        'An agent that can run shell commands can read its own environment, so every secret in scope is one instruction away from being printed, committed or sent elsewhere.',
      remediation: 'Scope secrets to the steps that need them rather than to the job.',
      evidence: [agentEvidence, blastEvidence],
    });
  }

  if (blast.secrets.includes('*inherit*')) {
    emit({
      ruleId: 'agent-inherits-all-secrets',
      severity: posture.privileged ? 'high' : 'medium',
      line: job.line,
      message: `Job "${job.id}" passes \`secrets: inherit\` to a workflow that runs ${describeAgent(agent)}.`,
      consequence:
        'The called workflow receives every secret in the repository, and nobody reading that workflow’s own file can see what it now has access to.',
      remediation: 'Pass named secrets instead of `inherit`.',
      evidence: [agentEvidence, blastEvidence],
    });
  }

  if (blast.permissionsUnset) {
    emit({
      ruleId: 'agent-permissions-unset',
      severity: posture.privileged ? 'medium' : 'low',
      line: job.line,
      message: `Neither the workflow nor job "${job.id}" declares \`permissions\`, and the job runs ${describeAgent(agent)}.`,
      consequence:
        'The repository default applies. Where that setting has not been changed it is write access to almost every scope, which is more capability than a reader of this file can tell it has.',
      remediation: 'Declare `permissions` explicitly — `permissions: {}` is a valid and useful answer.',
      evidence: [agentEvidence],
    });
  }

  for (const unpinned of agents.filter((candidate) => candidate.unpinned && candidate.uses !== null)) {
    emit({
      ruleId: 'unpinned-agent-action',
      severity: posture.privileged ? 'medium' : 'low',
      line: unpinned.line,
      message: `\`${unpinned.uses}\` is referenced by a tag or branch, not a commit.`,
      consequence:
        'Whoever controls that action repository can change what the tag points at, and the next run executes the new code with this job’s secrets and permissions.',
      remediation: 'Pin to a full commit SHA, with the version in a trailing comment.',
      evidence: [{ label: 'uses', detail: unpinned.uses ?? '', line: unpinned.line }],
    });
  }

  if (blast.selfHosted) {
    emit({
      ruleId: 'agent-on-self-hosted-runner',
      severity: reachable && posture.privileged ? 'high' : 'medium',
      line: job.line,
      message: `Job "${job.id}" runs ${describeAgent(agent)} on a self-hosted runner.`,
      consequence:
        'A hosted runner is destroyed after the job; a self-hosted one is not. Anything the agent is talked into leaving behind persists for later jobs, including jobs from other workflows.',
      remediation: 'Run agents on hosted runners, or on ephemeral self-hosted runners that can reach nothing else.',
      evidence: [agentEvidence, { label: 'runs-on', detail: job.runsOn.join(', '), line: job.line }],
    });
  }

  return findings;
}

/** True when outsider text can reach this agent today. */
function hasInjectionPath(
  analysis: JobAnalysis,
  agent: AgentDetection,
  posture: { untrusted: boolean },
): boolean {
  return analysis.sources.length > 0 || (agent.ingestsEvent && posture.untrusted);
}

/**
 * Adjust a rule's default severity for the job it fired in.
 *
 * Two things move it. A privileged trigger raises severity, because the run
 * holds secrets and a write token while an outsider writes its subject. A large
 * blast radius raises it again. An agent detected only as `possible` lowers it,
 * because the tool is guessing that a model is involved at all.
 */
function escalate(
  ruleId: string,
  privileged: boolean,
  blast: BlastRadius,
  agent: AgentDetection,
): Severity {
  let index = SEVERITIES.indexOf(defaultSeverityOf(ruleId));

  if (privileged) index -= 1;
  if (privileged && blast.score >= 50) index -= 1;
  // Without a privileged trigger the run has no secrets and a read-only token,
  // so the same construction is a much smaller problem.
  if (!privileged) index += 1;
  if (agent.confidence === 'possible') index += 1;

  const clamped = Math.max(0, Math.min(SEVERITIES.length - 1, index));
  return SEVERITIES[clamped] as Severity;
}

function describeAgent(agent: AgentDetection): string {
  if (agent.product !== null) return `\`${agent.product}\``;
  return agent.confidence === 'possible' ? 'a step that appears to call a model' : 'an AI agent';
}

function describeBlast(blast: BlastRadius): Evidence {
  const parts: string[] = [];

  if (blast.permissionsUnset) parts.push('permissions unset — repository default applies');
  else if (blast.writeScopes.length > 0) parts.push(`write: ${blast.writeScopes.join(', ')}`);
  else parts.push('no write scopes');

  if (blast.secrets.includes('*inherit*')) parts.push('inherits every repository secret');
  else if (blast.secrets.length > 0) parts.push(`${blast.secrets.length} secret(s) in scope`);

  if (blast.untrustedCheckout) parts.push('checks out outsider code');
  if (blast.selfHosted) parts.push('self-hosted runner');

  return { label: 'blast radius', detail: `${parts.join(' · ')} (${blast.score}/100)` };
}

function consequenceFor(posture: { privileged: boolean; names: string[] }, blast: BlastRadius): string {
  if (!posture.privileged) {
    return 'This trigger runs without repository secrets and with a read-only token, so an injection here cannot reach much — but the pattern becomes a takeover the moment the trigger or the permissions change.';
  }

  const capabilities: string[] = [];
  if (blast.writeScopes.includes('contents')) capabilities.push('push commits to this repository');
  if (blast.writeScopes.includes('actions')) capabilities.push('rewrite the workflows that would catch it');
  if (blast.writeScopes.includes('packages')) capabilities.push('publish packages');
  if (blast.oidc) capabilities.push('mint an OIDC token for whatever cloud account trusts this repository');
  if (blast.secrets.length > 0) capabilities.push('read the secrets in scope');
  if (blast.permissionsUnset) capabilities.push('use whatever the repository default token grants, which is often write');

  if (capabilities.length === 0) {
    return 'The run holds repository secrets and a token issued to the base repository, so instructions from an outsider are executed with more standing than they should have.';
  }

  return `Someone who can write that text is giving instructions to a job that can ${joinList(capabilities)}.`;
}

function writeConsequence(scopes: readonly string[]): string {
  const effects: string[] = [];
  if (scopes.includes('contents')) effects.push('push code — which on a repository that publishes from CI means shipping it');
  if (scopes.includes('actions')) effects.push('rewrite the workflows that would have caught it');
  if (scopes.includes('packages')) effects.push('publish packages');
  if (scopes.includes('id-token')) effects.push('mint a cloud credential through OIDC');
  if (scopes.includes('deployments')) effects.push('create deployments');

  return effects.length > 0
    ? `A hijacked agent here could ${joinList(effects)}.`
    : 'A hijacked agent here holds more write access than the task requires.';
}

function joinList(items: readonly string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}
