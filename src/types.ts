/**
 * The vocabulary.
 *
 * The model this tool is built on has three parts, and every type here belongs
 * to one of them:
 *
 *  - **Source** — text an outsider controls. An issue body, a pull request
 *    title, a branch name, a fork's description.
 *  - **Sink** — somewhere that text is interpreted as instruction rather than
 *    data. For this tool that means an AI agent's prompt.
 *  - **Blast radius** — what the job holding that sink is allowed to do.
 *    Permissions, secrets, the code it checked out, the runner it is on.
 *
 * A finding is a source reaching a sink inside a blast radius. None of the
 * three is a problem alone: untrusted text in a read-only job is fine, and an
 * agent with write permissions that only ever sees repository code is fine.
 * Severity comes from the combination, which is why the three are modelled
 * separately and joined late.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}

export function isAtLeast(severity: Severity, threshold: Severity): boolean {
  return compareSeverity(severity, threshold) <= 0;
}

/**
 * How an outsider gets text into a workflow run.
 *
 * `direct` means the text is interpolated into the workflow itself — a
 * `${{ github.event.issue.body }}` somewhere. `indirect` means the job goes and
 * fetches it: an agent told to read the pull request, a step that runs
 * `gh issue view`, a checkout of a fork's code. Indirect is the harder case and
 * the one most tooling misses, because there is no expression to grep for.
 */
export type SourceKind = 'direct' | 'indirect';

export interface UntrustedSource {
  readonly kind: SourceKind;
  /** The context expression or command that carries it. */
  readonly expression: string;
  /** What an outsider has to do to control it. */
  readonly control: string;
  /** Where it appears — `jobs.review.steps[2].with.prompt`. */
  readonly path: string;
  readonly line: number;
}

/** How confident the tool is that a step is really an AI agent. */
export type AgentConfidence = 'certain' | 'likely' | 'possible';

export interface AgentStep {
  readonly jobId: string;
  /** Index within the job's steps. */
  readonly stepIndex: number;
  readonly name: string | null;
  /** Action reference, when the agent is an action. */
  readonly uses: string | null;
  /** Product name, when recognised — `claude-code-action`, `aider`. */
  readonly product: string | null;
  readonly confidence: AgentConfidence;
  /** Why this step was identified as an agent. */
  readonly evidence: string;
  /** True when the action reference is not pinned to a commit SHA. */
  readonly unpinned: boolean;
  readonly line: number;
}

/** What a job is allowed to do, and therefore what a hijacked agent could do. */
export interface BlastRadius {
  /** Write scopes granted, resolved from job then workflow then default. */
  readonly writeScopes: readonly string[];
  /** True when no `permissions` block applies, so the repository default wins. */
  readonly permissionsUnset: boolean;
  /**
   * Secrets in scope, excluding GITHUB_TOKEN and the model provider key.
   *
   * The model key is separated because every agent needs one to exist at all.
   * Reporting it as an extra secret would mean firing on every agent workflow
   * ever written, including the ones that are doing everything right — and a
   * finding that is always present is a finding nobody reads.
   */
  readonly secrets: readonly string[];
  /** Model provider keys in scope, reported as context rather than as a finding. */
  readonly modelKeys: readonly string[];
  /** True when the job requests an OIDC token — credentials for other systems. */
  readonly oidc: boolean;
  /** True when the job checks out code an outsider can change. */
  readonly untrustedCheckout: boolean;
  /** True when the job runs on a self-hosted runner. */
  readonly selfHosted: boolean;
  /** 0–100, monotonic in the capability granted. */
  readonly score: number;
}

/** A trigger, and whether it runs privileged against outsider content. */
export interface TriggerFacts {
  readonly event: string;
  /**
   * True for the events that hand repository secrets and a write token to a
   * run whose subject an outsider controls: `pull_request_target`,
   * `workflow_run`, `issue_comment`, and friends.
   */
  readonly privileged: boolean;
  readonly line: number;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly workflow: string;
  readonly jobId: string;
  readonly line: number;
  /** One sentence: what is wrong. */
  readonly message: string;
  /** What an attacker could do with it, concretely. */
  readonly consequence: string;
  /** What to change. */
  readonly remediation: string;
  readonly evidence: readonly Evidence[];
}

export interface Evidence {
  readonly label: string;
  readonly detail: string;
  readonly line?: number;
}

export interface RuleDescriptor {
  readonly id: string;
  readonly title: string;
  readonly summary: string;
  readonly rationale: string;
  readonly remediation: string;
  readonly defaultSeverity: Severity;
}

/** Everything learned about one job. */
export interface JobAnalysis {
  readonly jobId: string;
  readonly name: string | null;
  readonly line: number;
  readonly agents: readonly AgentStep[];
  readonly sources: readonly UntrustedSource[];
  readonly blast: BlastRadius;
  readonly triggers: readonly TriggerFacts[];
}

export interface WorkflowAnalysis {
  /** Path relative to the scan root, POSIX-separated. */
  readonly path: string;
  readonly name: string | null;
  readonly triggers: readonly TriggerFacts[];
  readonly jobs: readonly JobAnalysis[];
  readonly findings: readonly Finding[];
  /** Parse problems. A workflow with these is reported, not silently skipped. */
  readonly errors: readonly { readonly line: number; readonly message: string }[];
  readonly unanalysable: boolean;
}

export interface ScanSummary {
  readonly workflows: number;
  readonly unanalysable: number;
  readonly jobs: number;
  readonly agentJobs: number;
  readonly findings: number;
  readonly bySeverity: Readonly<Record<Severity, number>>;
}

export interface ScanReport {
  readonly schemaVersion: 1;
  readonly tool: { readonly name: string; readonly version: string };
  readonly root: string;
  readonly summary: ScanSummary;
  readonly workflows: readonly WorkflowAnalysis[];
}
