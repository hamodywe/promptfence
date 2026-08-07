/**
 * The library surface.
 *
 * Everything the CLI does is reachable from here, so a project that wants to
 * enforce its own policy — treat `agent-permissions-unset` as blocking, or
 * route findings into its own tracker — can do so without shelling out and
 * parsing text. The exported types are the same ones `--json` serialises.
 */

export { scan, allFindings, VERSION, type ScanOptions, type ScanResult } from './scan.ts';
export { evaluateGate, type GateOptions, type GateResult } from './gate.ts';

export {
  CONFIG_FILENAME,
  DEFAULT_CONFIG,
  isExcluded,
  loadConfig,
  parseConfig,
  type Config,
  type LoadedConfig,
} from './config.ts';

export { RULES, ruleById, defaultSeverityOf } from './rules/catalog.ts';
export { analyseWorkflow } from './rules/evaluate.ts';

export { detectAgents, hasModelKey, type AgentDetection } from './analysis/agents.ts';
export {
  carriesUntrustedContent,
  expressionsIn,
  fetchCommandsIn,
  isPrivilegedTrigger,
  untrustedReferencesIn,
  type ContextMatch,
} from './analysis/contexts.ts';
export {
  checksOutUntrustedCode,
  computeBlastRadius,
  notableScopes,
  resolvePermissions,
  runsSelfHosted,
  secretsInScope,
  type PermissionResolution,
} from './analysis/blast.ts';

export { discoverWorkflows, type DiscoveryResult, type WorkflowFile } from './workflow/discover.ts';
export {
  flattenText,
  isPinnedToSha,
  parseWorkflow,
  splitActionRef,
  stepText,
  type Job,
  type Step,
  type Trigger,
  type Workflow,
} from './workflow/model.ts';
export { parseYaml, type YamlDocument, type YamlValue } from './yaml/parse.ts';

export { renderJson, type JsonOptions } from './report/json.ts';
export { renderMarkdown, type MarkdownOptions } from './report/markdown.ts';
export { renderSarif } from './report/sarif.ts';
export { renderTerminal, type TerminalOptions } from './report/terminal.ts';

export type {
  AgentConfidence,
  AgentStep,
  BlastRadius,
  Evidence,
  Finding,
  JobAnalysis,
  RuleDescriptor,
  ScanReport,
  ScanSummary,
  Severity,
  SourceKind,
  TriggerFacts,
  UntrustedSource,
  WorkflowAnalysis,
} from './types.ts';

export { SEVERITIES, compareSeverity, isAtLeast } from './types.ts';
