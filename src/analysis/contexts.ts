/**
 * Where an outsider's words get in.
 *
 * GitHub Actions exposes the triggering event as a context object, and parts of
 * that object are written by whoever opened the issue or the pull request. An
 * issue body is a text field with no meaningful constraints; so is a comment, a
 * pull request title, and — the one people forget — a branch name.
 *
 * The distinction that matters most here is **which events give a run
 * repository secrets and a write token while its subject is outsider-controlled.**
 * Generic advice blurs this, and blurring it produces both false alarms and
 * missed findings:
 *
 *  - `pull_request` from a fork runs with a read-only token and **no secrets**.
 *    Untrusted text in that job is a much smaller problem, and treating it as
 *    critical is how a security tool teaches people to ignore it.
 *  - `pull_request_target`, `issue_comment`, `issues`, `discussion*` and
 *    `workflow_run` run in the **base** repository's context, with secrets and a
 *    writable token, while the content that drives them is written by anyone
 *    with a GitHub account.
 *
 * That second list is where prompt injection into a CI agent stops being a
 * curiosity and becomes a repository takeover.
 */

/** Events whose payload carries text an outsider writes. */
const UNTRUSTED_CONTENT_EVENTS = new Set([
  'issues',
  'issue_comment',
  'discussion',
  'discussion_comment',
  'pull_request',
  'pull_request_target',
  'pull_request_review',
  'pull_request_review_comment',
  'workflow_run',
  'fork',
  'watch',
  'gollum',
]);

/**
 * Events that combine outsider-controlled content with the base repository's
 * secrets and a writable token.
 *
 * `pull_request` is deliberately absent: from a fork it gets neither.
 */
const PRIVILEGED_EVENTS = new Set([
  'issues',
  'issue_comment',
  'discussion',
  'discussion_comment',
  'pull_request_target',
  'pull_request_review',
  'pull_request_review_comment',
  'workflow_run',
  'gollum',
]);

export function carriesUntrustedContent(event: string): boolean {
  return UNTRUSTED_CONTENT_EVENTS.has(event);
}

export function isPrivilegedTrigger(event: string): boolean {
  return PRIVILEGED_EVENTS.has(event);
}

interface ContextPattern {
  readonly pattern: RegExp;
  /** What an outsider has to do to control this value. */
  readonly control: string;
}

/**
 * Context paths an outsider controls.
 *
 * Ordered most specific first, so that the reported reason is the precise one —
 * "the body of an issue comment" rather than "somewhere in the event payload".
 */
const UNTRUSTED_CONTEXTS: readonly ContextPattern[] = [
  {
    pattern: /github\.event\.comment\.body/,
    control: 'anyone who can comment on an issue or pull request writes this',
  },
  {
    pattern: /github\.event\.issue\.(?:body|title)/,
    control: 'anyone who can open an issue writes this',
  },
  {
    pattern: /github\.event\.pull_request\.(?:body|title)/,
    control: 'anyone who can open a pull request writes this',
  },
  {
    pattern: /github\.event\.(?:review|review_comment)\.body/,
    control: 'anyone who can review a pull request writes this',
  },
  {
    pattern: /github\.event\.discussion(?:_comment)?\.(?:body|title)/,
    control: 'anyone who can post in discussions writes this',
  },
  {
    pattern: /github\.(?:head_ref)|github\.event\.pull_request\.head\.(?:ref|label)/,
    control: 'a branch name on the contributor’s fork — free text, and easy to overlook',
  },
  {
    pattern: /github\.event\.pull_request\.head\.repo\.(?:description|homepage|full_name|owner)/,
    control: 'metadata on the contributor’s own fork',
  },
  {
    pattern: /github\.event\.(?:head_commit|commits\[\d+\])\.(?:message|author)/,
    control: 'a commit message, which anyone opening a pull request writes',
  },
  {
    pattern: /github\.event\.workflow_run\.(?:head_branch|head_commit)/,
    control: 'a branch or commit from the run that triggered this one',
  },
  {
    pattern: /github\.event\.pages\[\d+\]\.(?:page_name|title)/,
    control: 'a wiki page title, which any wiki contributor writes',
  },
  {
    pattern: /github\.(?:actor|triggering_actor)\b/,
    control: 'a GitHub username, which anyone can choose when creating an account',
  },
];

export interface ContextMatch {
  readonly expression: string;
  readonly control: string;
}

/** Extract every `${{ … }}` expression from a piece of text. */
export function expressionsIn(text: string): string[] {
  const found: string[] = [];
  const pattern = /\$\{\{([\s\S]*?)\}\}/g;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const inner = match[1]?.trim();
    if (inner !== undefined && inner !== '') found.push(inner);
  }

  return found;
}

/**
 * Find outsider-controlled context references in a piece of text.
 *
 * Both interpolated expressions and bare references are checked. The bare case
 * is not hypothetical: `env.ISSUE_BODY` set from the event elsewhere, or a
 * `github.event.issue.body` written inside an agent's prompt template, reaches
 * the model just as effectively without `${{ }}` around it at the point of use.
 */
export function untrustedReferencesIn(text: string): ContextMatch[] {
  const matches: ContextMatch[] = [];
  const seen = new Set<string>();

  for (const context of UNTRUSTED_CONTEXTS) {
    const found = context.pattern.exec(text);
    if (found === null) continue;

    const expression = found[0];
    if (seen.has(expression)) continue;
    seen.add(expression);
    matches.push({ expression, control: context.control });
  }

  return matches;
}

/**
 * Commands that go and fetch outsider-controlled text.
 *
 * This is the case with no expression to grep for: the workflow does not
 * interpolate anything, it runs `gh pr view` and pipes the result into a
 * prompt. Static analysis that only looks at `${{ }}` misses it entirely.
 */
const FETCH_COMMANDS: readonly ContextPattern[] = [
  {
    pattern: /\bgh\s+(?:issue|pr|release)\s+(?:view|list|diff)\b/,
    control: 'the command fetches issue or pull request text written by outsiders',
  },
  {
    pattern: /\bgh\s+api\s+\S*(?:issues|pulls|comments|discussions)/,
    control: 'the command fetches issue or pull request text written by outsiders',
  },
  {
    pattern: /\bgit\s+log\b[^\n|]*(?:--format|--pretty|-p\b)/,
    control: 'commit messages and diffs, which a contributor writes',
  },
  {
    pattern: /\bcurl\b[^\n]*api\.github\.com\/repos\/[^\n]*(?:issues|pulls|comments)/,
    control: 'the command fetches issue or pull request text written by outsiders',
  },
];

export function fetchCommandsIn(text: string): ContextMatch[] {
  const matches: ContextMatch[] = [];

  for (const command of FETCH_COMMANDS) {
    const found = command.pattern.exec(text);
    if (found !== null) matches.push({ expression: found[0].trim(), control: command.control });
  }

  return matches;
}
