/**
 * Recognising the step that talks to a model.
 *
 * This is the sink. Everything else in the analysis is about what flows into it
 * and what surrounds it, so a missed agent means a missed finding — and a step
 * wrongly called an agent means a false alarm on a workflow that never touches
 * a model.
 *
 * Detection is layered, and each layer reports its own confidence rather than
 * pretending to the same certainty:
 *
 *  - **certain** — a known agent action. There is no ambiguity about what
 *    `anthropics/claude-code-action` does.
 *  - **likely** — a known agent CLI invoked from a `run:` block.
 *  - **possible** — a model provider's API key in scope with no recognised
 *    agent. Something here talks to a model; the tool cannot say what.
 *
 * The `possible` tier exists because the space moves faster than any catalogue.
 * A workflow using a wrapper published last week will not be in the list below,
 * but it will still need an API key, and a finding that says "this step has an
 * Anthropic key and reads issue text" is useful even when the tool cannot name
 * the product.
 */

import { splitActionRef, isPinnedToSha, stepText, type Step } from '../workflow/model.ts';
import type { AgentConfidence, AgentStep } from '../types.ts';

interface KnownAgent {
  /** Matched against the action reference with the version stripped. */
  readonly action: RegExp;
  readonly product: string;
  /**
   * True when the action reads the triggering event's payload into its own
   * context by design. These are the ones where there is no `${{ }}` to find:
   * the workflow passes nothing, and the agent still ends up holding the text
   * of the comment that triggered it.
   */
  readonly ingestsEvent: boolean;
}

const KNOWN_AGENT_ACTIONS: readonly KnownAgent[] = [
  { action: /^anthropics\/claude-code-action$/i, product: 'claude-code-action', ingestsEvent: true },
  { action: /^anthropics\/claude-code-base-action$/i, product: 'claude-code-base-action', ingestsEvent: false },
  { action: /^openai\/codex-action$/i, product: 'codex-action', ingestsEvent: true },
  { action: /^google-github-actions\/run-gemini-cli$/i, product: 'gemini-cli', ingestsEvent: true },
  { action: /^google-gemini\/gemini-cli-action$/i, product: 'gemini-cli', ingestsEvent: true },
  { action: /^cursor\/[a-z-]*agent[a-z-]*$/i, product: 'cursor-agent', ingestsEvent: true },
  { action: /^All-Hands-AI\/[a-z-]*openhands[a-z-]*$/i, product: 'openhands', ingestsEvent: true },
  { action: /^block\/goose[a-z-]*$/i, product: 'goose', ingestsEvent: false },
  { action: /^continuedev\/[a-z-]+$/i, product: 'continue', ingestsEvent: false },
  { action: /^sweepai\/[a-z-]+$/i, product: 'sweep', ingestsEvent: true },
  { action: /^aider-ai\/[a-z-]+$/i, product: 'aider', ingestsEvent: false },
  { action: /^github\/copilot[a-z-]*$/i, product: 'copilot', ingestsEvent: true },
  { action: /^[\w.-]+\/[a-z-]*(?:claude-code|codex-cli|opencode)[a-z-]*$/i, product: 'agent action', ingestsEvent: false },
];

/** Agent CLIs invoked from a shell step. */
const AGENT_COMMANDS: readonly { readonly pattern: RegExp; readonly product: string }[] = [
  { pattern: /(?:^|[\s;&|])claude(?:\s+-|\s+--|\s+"|\s+'|\s+\$)/m, product: 'claude code' },
  { pattern: /@anthropic-ai\/claude-code/, product: 'claude code' },
  { pattern: /(?:^|[\s;&|])aider\s/m, product: 'aider' },
  { pattern: /(?:^|[\s;&|])codex\s/m, product: 'codex' },
  { pattern: /(?:^|[\s;&|])opencode\s/m, product: 'opencode' },
  { pattern: /(?:^|[\s;&|])cursor-agent\s/m, product: 'cursor-agent' },
  { pattern: /(?:^|[\s;&|])gemini\s+(?:-p|--prompt)/m, product: 'gemini cli' },
  { pattern: /(?:^|[\s;&|])goose\s+run\b/m, product: 'goose' },
  { pattern: /(?:^|[\s;&|])llm\s+(?:-m|--model|"|')/m, product: 'llm cli' },
  { pattern: /openai\s+api\s+\w+\.create/, product: 'openai cli' },
];

/** Environment variables that only exist to authenticate against a model. */
const MODEL_KEY_PATTERN =
  /\b(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|MISTRAL_API_KEY|GROQ_API_KEY|COHERE_API_KEY|OPENROUTER_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|AZURE_OPENAI_API_KEY)\b/;

/** Endpoints that identify a raw HTTP call to a model provider. */
const MODEL_ENDPOINT_PATTERN =
  /\b(?:api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai)\b/;

export interface AgentDetection extends AgentStep {
  /** True when this agent reads the triggering event by design. */
  readonly ingestsEvent: boolean;
}

/**
 * Identify the agent steps in a job.
 *
 * A step is reported at most once, at the highest confidence that matched.
 */
export function detectAgents(jobId: string, steps: readonly Step[]): AgentDetection[] {
  const found: AgentDetection[] = [];

  for (const [index, step] of steps.entries()) {
    const detection = detectAgent(jobId, index, step);
    if (detection !== undefined) found.push(detection);
  }

  return found;
}

function detectAgent(jobId: string, index: number, step: Step): AgentDetection | undefined {
  const text = [...stepText(step).values()].join('\n');

  if (step.uses !== null) {
    const { action, ref } = splitActionRef(step.uses);

    for (const known of KNOWN_AGENT_ACTIONS) {
      if (!known.action.test(action)) continue;
      return build(jobId, index, step, {
        product: known.product,
        confidence: 'certain',
        evidence: `uses ${step.uses}`,
        ingestsEvent: known.ingestsEvent,
        unpinned: !isPinnedToSha(ref),
      });
    }
  }

  if (step.run !== null) {
    for (const command of AGENT_COMMANDS) {
      if (!command.pattern.test(step.run)) continue;
      return build(jobId, index, step, {
        product: command.product,
        confidence: 'likely',
        evidence: `runs ${command.product}`,
        ingestsEvent: false,
        unpinned: false,
      });
    }
  }

  const endpoint = MODEL_ENDPOINT_PATTERN.exec(text);
  if (endpoint !== null) {
    return build(jobId, index, step, {
      product: null,
      confidence: 'likely',
      evidence: `calls ${endpoint[0]} directly`,
      ingestsEvent: false,
      unpinned: false,
    });
  }

  const key = MODEL_KEY_PATTERN.exec(text);
  if (key !== null) {
    return build(jobId, index, step, {
      product: null,
      confidence: 'possible',
      evidence: `${key[0]} is in scope for this step`,
      ingestsEvent: false,
      unpinned: false,
    });
  }

  return undefined;
}

function build(
  jobId: string,
  stepIndex: number,
  step: Step,
  detail: {
    product: string | null;
    confidence: AgentConfidence;
    evidence: string;
    ingestsEvent: boolean;
    unpinned: boolean;
  },
): AgentDetection {
  return {
    jobId,
    stepIndex,
    name: step.name,
    uses: step.uses,
    product: detail.product,
    confidence: detail.confidence,
    evidence: detail.evidence,
    ingestsEvent: detail.ingestsEvent,
    unpinned: detail.unpinned,
    line: step.line,
  };
}

/**
 * Whether a model key is in scope for a whole job or workflow rather than one
 * step, which is how a `possible` agent ends up spread across every step.
 */
export function hasModelKey(text: string): boolean {
  return MODEL_KEY_PATTERN.test(text);
}

/**
 * Whether a secret name is a model provider key.
 *
 * Used to keep the key an agent cannot run without out of the "extra secrets in
 * scope" finding. It is still reported as context — it is the one secret whose
 * theft is a billing problem rather than a breach — but it is not a defect.
 */
export function isModelKeyName(name: string): boolean {
  return MODEL_KEY_PATTERN.test(name);
}
