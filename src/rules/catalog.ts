/**
 * The rules, and what each one is really claiming.
 *
 * Every rule states a consequence rather than a policy. "Do not interpolate
 * untrusted input" is advice; "an attacker who comments on any issue can make
 * this agent push to main" is a claim someone can check, disagree with, and act
 * on. The second kind gets fixed.
 *
 * Severities here are defaults. The evaluator raises and lowers them from the
 * facts of the job — chiefly whether the trigger hands out secrets and a write
 * token, because the same interpolation is a repository takeover under
 * `issue_comment` and close to harmless under a fork's `pull_request`.
 */

import type { RuleDescriptor, Severity } from '../types.ts';

export const RULES: readonly RuleDescriptor[] = [
  {
    id: 'agent-reads-interpolated-input',
    title: 'Outsider-controlled text is interpolated into an agent step',
    summary: 'A ${{ }} expression an outsider writes is placed into an AI agent step.',
    rationale:
      'The value is pasted into the step before the agent runs, so whatever the outsider wrote arrives as part of the agent’s instructions. Models do not reliably distinguish the data they were given from the instructions they were given, and an agent with tools acts on what it decides its instructions are.',
    remediation:
      'Pass the text through an environment variable and tell the agent to treat it as data, not instruction. Better: move the privileged work to a second job that receives only a structured result, so the agent that reads outsider text has no permissions of its own.',
    defaultSeverity: 'high',
  },
  {
    id: 'agent-ingests-untrusted-event',
    title: 'An agent reads the triggering event, which an outsider wrote',
    summary:
      'This agent action reads the event payload by design, and the workflow is triggered by an event whose content outsiders control.',
    rationale:
      'There is no ${{ }} to find here — the workflow passes nothing and the agent still ends up holding the text of the comment that triggered it. This is the case tooling that greps for template injection misses completely, and it is the most common shape in practice, because it is what the quickstart in every agent action’s README produces.',
    remediation:
      'Restrict who can trigger the run — an `if` on `github.event.comment.author_association` being OWNER, MEMBER or COLLABORATOR is the usual answer — and cut the job’s permissions to the minimum the task needs.',
    defaultSeverity: 'high',
  },
  {
    id: 'agent-fetches-untrusted-content',
    title: 'A step fetches outsider-written text into a job that runs an agent',
    summary: 'A command in this job retrieves issue, pull request or commit text that outsiders write.',
    rationale:
      'The text does not have to arrive through the event payload. A step that runs `gh pr view` and pipes the result into a prompt has the same problem, and neither the workflow nor the event payload shows an expression to flag.',
    remediation:
      'Treat fetched text as untrusted at the point it is fetched. If the agent needs it, hand it over as data with an explicit instruction not to follow it, and keep privileged capability out of the same job.',
    defaultSeverity: 'medium',
  },
  {
    id: 'untrusted-checkout-with-agent',
    title: 'A privileged job checks out outsider code and runs an agent',
    summary:
      'This job runs on a trigger that grants secrets and a write token, checks out the contributor’s code, and runs an AI agent.',
    rationale:
      'The contributor controls the files the agent reads. Instructions can be placed in a README, a comment, a test fixture — anywhere the agent will look — and the agent is holding the base repository’s secrets while it reads them. The classic form of this bug does not even need the agent: the checked-out code can be executed by the build. The agent widens it to every file it opens.',
    remediation:
      'Do not check out pull request head code in a `pull_request_target` or `workflow_run` job. Split it: an unprivileged job builds and uploads an artefact, a privileged job consumes the result.',
    defaultSeverity: 'critical',
  },
  {
    id: 'agent-holds-write-permissions',
    title: 'An agent runs with write permissions',
    summary: 'The job running this agent has write access to scopes whose abuse is not easily undone.',
    rationale:
      'This is the blast radius. `contents: write` means pushing code, which on a repository with a publish workflow means shipping it. `actions: write` means rewriting the workflows that would have caught it. `id-token: write` means minting a credential for whatever cloud account trusts this repository, which is frequently the largest thing in reach.',
    remediation:
      'Set `permissions` on the job to the narrowest set the task needs. If the agent only comments, `issues: write` and `pull-requests: write` are enough; it does not need `contents`.',
    defaultSeverity: 'medium',
  },
  {
    id: 'agent-holds-secrets',
    title: 'Repository secrets are in scope where an agent runs',
    summary: 'Secrets beyond GITHUB_TOKEN are available to the step or job running the agent.',
    rationale:
      'An agent that can run shell commands can read its own environment. Once outsider text reaches it, every secret in scope is one persuasive instruction away from being printed, committed, or sent somewhere.',
    remediation:
      'Move secrets to the steps that need them rather than the job. If the agent needs a model key and nothing else, that is the only secret that should be in its environment.',
    defaultSeverity: 'medium',
  },
  {
    id: 'agent-inherits-all-secrets',
    title: 'A called workflow running an agent inherits every secret',
    summary: '`secrets: inherit` passes the whole repository secret store to the called workflow.',
    rationale:
      'Inheritance is transitive and invisible from the called workflow’s own file. Nobody reviewing that file can see what it now has access to, and adding a secret to the repository silently widens it further.',
    remediation: 'Pass named secrets instead of `inherit`.',
    defaultSeverity: 'high',
  },
  {
    id: 'agent-permissions-unset',
    title: 'A job running an agent sets no permissions',
    summary: 'Neither the workflow nor the job declares `permissions`, so the repository default applies.',
    rationale:
      'The default is a repository setting this analysis cannot see. On repositories created before February 2023, or where the setting was never changed, it is write access to almost every scope. An agent inheriting that has more capability than anyone reviewing the workflow can tell from reading it.',
    remediation:
      'Declare `permissions` explicitly, even when the answer is `permissions: {}`. Being able to see the answer in the file is most of the value.',
    defaultSeverity: 'low',
  },
  {
    id: 'unpinned-agent-action',
    title: 'An agent action is not pinned to a commit',
    summary: 'The action reference uses a tag or branch, which the publisher can move.',
    rationale:
      'A tag is a pointer, not a version. Whoever controls the action repository can change what a tag points at, and the next run of this workflow executes the new code with the job’s secrets and permissions. For an action whose job is to run a model with tool access, that is a large amount of trust to place in a mutable reference.',
    remediation:
      'Pin to a full commit SHA and record the version beside it in a comment. Dependabot updates SHA pins.',
    defaultSeverity: 'low',
  },
  {
    id: 'agent-on-self-hosted-runner',
    title: 'An agent runs on a self-hosted runner',
    summary: 'This job runs on infrastructure you operate rather than a disposable hosted runner.',
    rationale:
      'A hosted runner is destroyed after the job. A self-hosted one is not: anything an agent is talked into leaving behind — a modified tool on the PATH, a background process, a cached credential — is there for the next job, including jobs from other workflows.',
    remediation:
      'Run agents on hosted runners. If a self-hosted runner is unavoidable, use ephemeral runners in a network segment that can reach nothing else.',
    defaultSeverity: 'medium',
  },
];

const BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));

export function ruleById(id: string): RuleDescriptor | undefined {
  return BY_ID.get(id);
}

export function defaultSeverityOf(id: string): Severity {
  return BY_ID.get(id)?.defaultSeverity ?? 'medium';
}
