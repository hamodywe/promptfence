/**
 * A dependency-free YAML parser covering the subset GitHub Actions workflows use.
 *
 * Two reasons not to take a dependency here.
 *
 * The first is that this tool is pointed at repositories, including forks and
 * untrusted pull requests. A parser is the component that touches hostile input
 * first, and a full YAML implementation is a large attack surface — the
 * billion-laughs class of denial-of-service exists precisely because YAML
 * aliases can expand exponentially. This parser has no alias mechanism at all,
 * so that class is structurally impossible rather than mitigated.
 *
 * The second is position tracking. Every value carries the line it came from,
 * which is what lets a finding point at `line 34` of a workflow rather than at
 * the file. General-purpose parsers discard that by the time you have a plain
 * object, and reconstructing it afterwards by searching for the key is
 * guesswork that breaks on repeated keys.
 *
 * What is covered: block mappings and sequences at arbitrary nesting, flow
 * mappings and sequences, literal (`|`) and folded (`>`) block scalars with
 * chomping indicators, single- and double-quoted scalars with escapes,
 * multi-line plain scalars, comments, and documents with or without a leading
 * `---`.
 *
 * What is refused, loudly rather than silently: anchors, aliases, merge keys,
 * explicit tags, and complex keys. GitHub Actions supports some of these, so a
 * workflow using them is reported as unanalysable rather than analysed wrongly.
 * A security verdict computed from a half-parsed workflow is worse than no verdict.
 */

export type YamlValue = string | number | boolean | null | YamlValue[] | YamlMap;
export interface YamlMap {
  [key: string]: YamlValue;
}

export interface YamlError {
  /** 1-based line number. */
  readonly line: number;
  readonly message: string;
}

export interface YamlDocument {
  readonly value: YamlValue;
  readonly errors: readonly YamlError[];
  /**
   * Line number for each mapping path, keyed by dotted path
   * (`jobs.build.strategy.matrix`). Sequence indices appear as `[0]`.
   */
  readonly lines: ReadonlyMap<string, number>;
}

interface Line {
  readonly raw: string;
  /** Content with any trailing comment removed. */
  readonly content: string;
  readonly indent: number;
  /** 1-based line number. */
  readonly number: number;
}

const UNSUPPORTED: readonly (readonly [RegExp, string])[] = [
  [/^&\S/, 'YAML anchors are not supported'],
  [/^\*\S/, 'YAML aliases are not supported'],
  [/^!!?\S/, 'YAML tags are not supported'],
  [/^\?\s/, 'YAML complex keys are not supported'],
];

/** Remove a trailing comment, respecting quotes and expression syntax. */
function stripComment(text: string): string {
  let single = false;
  let double = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (ch === "'" && !double) {
      single = !single;
    } else if (ch === '"' && !single && text[i - 1] !== '\\') {
      double = !double;
    } else if (ch === '#' && !single && !double) {
      // Only a whitespace-preceded hash starts a comment, which keeps
      // `image: node:20#sha` and URL fragments intact.
      const previous = i === 0 ? ' ' : text[i - 1];
      if (previous === ' ' || previous === '\t' || i === 0) return text.slice(0, i);
    }
  }

  return text;
}

function indentOf(raw: string): number {
  let n = 0;
  while (n < raw.length && (raw[n] === ' ' || raw[n] === '\t')) n += 1;
  return n;
}

function decodeDoubleQuoted(text: string, line: number, errors: YamlError[]): string {
  let out = '';

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch !== '\\') {
      out += ch;
      continue;
    }

    i += 1;
    const escape = text[i];
    switch (escape) {
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case '0': out += '\0'; break;
      case '"': out += '"'; break;
      case "'": out += "'"; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'u': {
        const hex = text.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          errors.push({ line, message: `invalid \\u escape: expected four hex digits, got "${hex}"` });
          out += '\\u';
          break;
        }
        out += String.fromCharCode(Number.parseInt(hex, 16));
        i += 4;
        break;
      }
      default:
        out += escape ?? '';
    }
  }

  return out;
}

/**
 * Interpret a plain scalar using YAML's core schema.
 *
 * One deliberate deviation: the YAML 1.1 booleans `on`, `off`, `yes` and `no`
 * are **not** coerced. In a workflow file the top-level key is literally `on:`,
 * and a parser that helpfully turns it into the boolean `true` produces a
 * workflow with no triggers and no error — the single most notorious bug in
 * this file format. Only `true` and `false` are booleans here.
 */
function coercePlain(text: string): YamlValue {
  const trimmed = text.trim();

  if (trimmed === '') return '';
  if (trimmed === '~' || trimmed === 'null' || trimmed === 'Null' || trimmed === 'NULL') return null;
  if (trimmed === 'true' || trimmed === 'True' || trimmed === 'TRUE') return true;
  if (trimmed === 'false' || trimmed === 'False' || trimmed === 'FALSE') return false;

  // Version-like values ("3.10", "1.2.3") must stay strings: coercing "3.10" to
  // the number 3.1 silently rewrites a Python version in a matrix.
  if (/^[-+]?\d+$/.test(trimmed)) {
    const value = Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(value) ? value : trimmed;
  }

  return trimmed;
}

function parseScalar(text: string, line: number, errors: YamlError[]): YamlValue {
  const trimmed = text.trim();

  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return decodeDoubleQuoted(trimmed.slice(1, -1), line, errors);
  }
  if (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  if ((trimmed.startsWith('"') || trimmed.startsWith("'")) && trimmed.length > 1) {
    errors.push({ line, message: 'unterminated quoted string' });
    return trimmed.slice(1);
  }

  return coercePlain(trimmed);
}

/** Split a flow collection body on top-level commas. */
function splitFlow(body: string): string[] {
  const parts: string[] = [];
  let current = '';
  let depth = 0;
  let single = false;
  let double = false;

  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i] as string;

    if (ch === "'" && !double) single = !single;
    else if (ch === '"' && !single && body[i - 1] !== '\\') double = !double;
    else if (!single && !double && (ch === '[' || ch === '{')) depth += 1;
    else if (!single && !double && (ch === ']' || ch === '}')) depth -= 1;
    else if (ch === ',' && !single && !double && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.trim() !== '') parts.push(current);
  return parts;
}

function parseFlow(text: string, line: number, errors: YamlError[]): YamlValue {
  const trimmed = text.trim();

  if (trimmed.startsWith('[')) {
    if (!trimmed.endsWith(']')) {
      errors.push({ line, message: 'unterminated flow sequence' });
      return [];
    }
    const body = trimmed.slice(1, -1);
    if (body.trim() === '') return [];
    return splitFlow(body).map((part) => parseFlowItem(part, line, errors));
  }

  if (trimmed.startsWith('{')) {
    if (!trimmed.endsWith('}')) {
      errors.push({ line, message: 'unterminated flow mapping' });
      return {};
    }
    const body = trimmed.slice(1, -1);
    const map: YamlMap = {};
    if (body.trim() === '') return map;

    for (const entry of splitFlow(body)) {
      const colon = findKeyColon(entry);
      if (colon === -1) {
        errors.push({ line, message: `flow mapping entry "${entry.trim()}" is missing a value` });
        continue;
      }
      map[entry.slice(0, colon).trim().replace(/^["']|["']$/g, '')] =
        parseFlowItem(entry.slice(colon + 1), line, errors);
    }
    return map;
  }

  return parseScalar(trimmed, line, errors);
}

function parseFlowItem(text: string, line: number, errors: YamlError[]): YamlValue {
  const trimmed = text.trim();
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) return parseFlow(trimmed, line, errors);
  return parseScalar(trimmed, line, errors);
}

/**
 * Index of the colon separating a key from its value, or -1.
 *
 * A colon only ends a key when followed by whitespace or end of line. This is
 * what keeps `image: ubuntu:22.04` and `run: curl https://x.dev` from splitting
 * in the wrong place.
 */
function findKeyColon(text: string): number {
  let single = false;
  let double = false;
  let depth = 0;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (ch === "'" && !double) single = !single;
    else if (ch === '"' && !single && text[i - 1] !== '\\') double = !double;
    else if (!single && !double && (ch === '[' || ch === '{')) depth += 1;
    else if (!single && !double && (ch === ']' || ch === '}')) depth -= 1;
    else if (ch === ':' && !single && !double && depth === 0) {
      const next = text[i + 1];
      if (next === undefined || next === ' ' || next === '\t') return i;
    }
  }

  return -1;
}

interface State {
  readonly lines: readonly Line[];
  readonly errors: YamlError[];
  readonly positions: Map<string, number>;
}

function isBlank(line: Line): boolean {
  return line.content.trim() === '';
}

function skipBlank(state: State, from: number): number {
  let i = from;
  while (i < state.lines.length && isBlank(state.lines[i] as Line)) i += 1;
  return i;
}

/**
 * Read a `|` or `>` block scalar.
 *
 * These matter more here than in most formats: every `run:` step in a workflow
 * is one, and their content is what security and waste rules are matched
 * against. Getting the de-indentation wrong corrupts the shell script.
 */
function readBlockScalar(
  state: State,
  start: number,
  parentIndent: number,
  header: string,
): { value: string; next: number } {
  const folded = header.trimStart().startsWith('>');
  const chomp = header.includes('-') ? 'strip' : header.includes('+') ? 'keep' : 'clip';

  // An explicit indentation indicator ("|2") pins the block indent, which
  // matters when the first line is itself indented relative to the rest.
  const explicit = /[|>][+-]?(\d+)/.exec(header);
  let blockIndent = explicit?.[1] === undefined ? -1 : parentIndent + Number.parseInt(explicit[1], 10);

  const collected: string[] = [];
  let index = start;

  while (index < state.lines.length) {
    const line = state.lines[index] as Line;

    if (line.raw.trim() === '') {
      collected.push('');
      index += 1;
      continue;
    }
    if (line.indent <= parentIndent) break;

    if (blockIndent === -1) blockIndent = line.indent;
    collected.push(line.raw.length >= blockIndent ? line.raw.slice(blockIndent) : line.raw.trimStart());
    index += 1;
  }

  while (collected.length > 0 && collected[collected.length - 1] === '') collected.pop();

  let value: string;
  if (folded) {
    const paragraphs: string[] = [];
    let buffer: string[] = [];

    for (const entry of collected) {
      if (entry === '') {
        paragraphs.push(buffer.join(' '));
        buffer = [];
      } else if (entry.startsWith(' ') && buffer.length > 0) {
        // A more-indented line inside a folded block keeps its own break.
        paragraphs.push(buffer.join(' '));
        buffer = [entry.trim()];
      } else {
        buffer.push(entry.trim());
      }
    }
    if (buffer.length > 0) paragraphs.push(buffer.join(' '));
    value = paragraphs.join('\n');
  } else {
    value = collected.join('\n');
  }

  if (chomp === 'keep') value += '\n';
  else if (chomp === 'clip' && value !== '') value += '\n';

  return { value, next: index };
}

function joinPath(path: string, key: string): string {
  return path === '' ? key : `${path}.${key}`;
}

function parseNode(state: State, start: number, indent: number, path: string): { value: YamlValue; next: number } {
  const line = state.lines[start];
  if (line === undefined) return { value: null, next: start };

  const trimmed = line.content.trim();
  if (trimmed.startsWith('- ') || trimmed === '-') return parseSequence(state, start, indent, path);
  return parseMapping(state, start, indent, path);
}

/**
 * Anchors and aliases appearing as a *value* rather than at the start of a
 * line — `base: &defaults` and `job: *defaults`, which is how they are almost
 * always written. Detecting them only at line start would miss the common case
 * entirely and silently parse `&defaults` as the string "&defaults".
 */
const VALUE_ANCHOR = /^&\S/;
const VALUE_ALIAS = /^\*\S/;

function parseValue(
  state: State,
  keyLine: Line,
  rest: string,
  index: number,
  path: string,
): { value: YamlValue; next: number } {
  const trimmed = rest.trim();

  if (VALUE_ANCHOR.test(trimmed)) {
    state.errors.push({ line: keyLine.number, message: 'YAML anchors are not supported' });
    return { value: null, next: index };
  }
  if (VALUE_ALIAS.test(trimmed)) {
    state.errors.push({ line: keyLine.number, message: 'YAML aliases are not supported' });
    return { value: null, next: index };
  }

  if (trimmed.startsWith('|') || trimmed.startsWith('>')) {
    return readBlockScalar(state, index, keyLine.indent, trimmed);
  }
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    return { value: parseFlow(trimmed, keyLine.number, state.errors), next: index };
  }

  if (trimmed !== '') {
    // A plain scalar may continue on more-indented following lines.
    const parts = [trimmed];
    let cursor = index;
    const quoted = trimmed.startsWith('"') || trimmed.startsWith("'");

    if (!quoted) {
      while (cursor < state.lines.length) {
        const follow = state.lines[cursor] as Line;
        if (isBlank(follow) || follow.indent <= keyLine.indent) break;
        const text = follow.content.trim();
        if (text.startsWith('- ') || text === '-' || findKeyColon(text) !== -1) break;
        parts.push(text);
        cursor += 1;
      }
    }

    if (parts.length === 1) return { value: parseScalar(trimmed, keyLine.number, state.errors), next: index };
    return { value: coercePlain(parts.join(' ')), next: cursor };
  }

  // Empty value: a nested block below, or null.
  const peek = skipBlank(state, index);
  if (peek >= state.lines.length) return { value: null, next: index };

  const child = state.lines[peek] as Line;
  if (child.indent <= keyLine.indent) {
    // A sequence may be written at the same indentation as its key.
    const childText = child.content.trim();
    if (child.indent === keyLine.indent && (childText.startsWith('- ') || childText === '-')) {
      return parseSequence(state, peek, child.indent, path);
    }
    return { value: null, next: index };
  }

  return parseNode(state, peek, child.indent, path);
}

function parseSequence(state: State, start: number, indent: number, path: string): { value: YamlValue[]; next: number } {
  const items: YamlValue[] = [];
  let index = start;

  while (index < state.lines.length) {
    const line = state.lines[index] as Line;
    if (isBlank(line)) { index += 1; continue; }
    if (line.indent !== indent) break;

    const trimmed = line.content.trim();
    if (!trimmed.startsWith('- ') && trimmed !== '-') break;

    const itemPath = `${path}[${items.length}]`;
    state.positions.set(itemPath, line.number);

    const inline = trimmed === '-' ? '' : trimmed.slice(1).trim();
    index += 1;

    if (inline === '') {
      const peek = skipBlank(state, index);
      const child = peek < state.lines.length ? state.lines[peek] : undefined;
      if (child !== undefined && child.indent > indent) {
        const parsed = parseNode(state, peek, child.indent, itemPath);
        items.push(parsed.value);
        index = parsed.next;
      } else {
        items.push(null);
      }
      continue;
    }

    if (inline.startsWith('[') || inline.startsWith('{')) {
      items.push(parseFlow(inline, line.number, state.errors));
      continue;
    }

    // `- key: value` opens a mapping whose keys align just after the dash.
    const colon = findKeyColon(inline);
    if (colon !== -1) {
      const virtualIndent = indent + 2;
      const map: YamlMap = {};
      const key = inline.slice(0, colon).trim();
      const keyPath = joinPath(itemPath, key);
      state.positions.set(keyPath, line.number);

      const parsed = parseValue(
        state,
        { ...line, indent: virtualIndent, content: inline },
        inline.slice(colon + 1),
        index,
        keyPath,
      );
      map[key] = parsed.value;
      index = parsed.next;

      while (index < state.lines.length) {
        const follow = state.lines[index] as Line;
        if (isBlank(follow)) { index += 1; continue; }
        if (follow.indent <= indent) break;

        const followText = follow.content.trim();
        const followColon = findKeyColon(followText);
        if (followColon === -1) break;

        const followKey = followText.slice(0, followColon).trim();
        const followPath = joinPath(itemPath, followKey);
        state.positions.set(followPath, follow.number);

        const sub = parseValue(state, follow, followText.slice(followColon + 1), index + 1, followPath);
        map[followKey] = sub.value;
        index = sub.next;
      }

      items.push(map);
      continue;
    }

    items.push(parseScalar(inline, line.number, state.errors));
  }

  return { value: items, next: index };
}

function parseMapping(state: State, start: number, indent: number, path: string): { value: YamlMap; next: number } {
  const map: YamlMap = {};
  let index = start;

  while (index < state.lines.length) {
    const line = state.lines[index] as Line;
    if (isBlank(line)) { index += 1; continue; }
    if (line.indent < indent) break;

    const trimmed = line.content.trim();
    if (trimmed === '---' || trimmed === '...') break;

    if (line.indent > indent) {
      state.errors.push({
        line: line.number,
        message: `unexpected indentation: expected ${indent} spaces, found ${line.indent}`,
      });
      index += 1;
      continue;
    }

    for (const [pattern, message] of UNSUPPORTED) {
      if (pattern.test(trimmed)) {
        state.errors.push({ line: line.number, message });
        return { value: map, next: state.lines.length };
      }
    }

    if (trimmed.startsWith('<<:')) {
      state.errors.push({ line: line.number, message: 'YAML merge keys are not supported' });
      return { value: map, next: state.lines.length };
    }

    const colon = findKeyColon(trimmed);
    if (colon === -1) {
      state.errors.push({
        line: line.number,
        message: `expected "key: value" but found "${trimmed.slice(0, 60)}"`,
      });
      index += 1;
      continue;
    }

    const key = trimmed.slice(0, colon).trim().replace(/^["']|["']$/g, '');
    if (key === '') {
      state.errors.push({ line: line.number, message: 'mapping key is empty' });
      index += 1;
      continue;
    }

    const keyPath = joinPath(path, key);
    if (Object.prototype.hasOwnProperty.call(map, key)) {
      state.errors.push({ line: line.number, message: `duplicate key "${key}"` });
    }
    state.positions.set(keyPath, line.number);

    const parsed = parseValue(state, line, trimmed.slice(colon + 1), index + 1, keyPath);
    map[key] = parsed.value;
    index = parsed.next;
  }

  return { value: map, next: index };
}

/** Parse a YAML document into a plain value plus per-path line numbers. */
export function parseYaml(source: string): YamlDocument {
  const text = (source.charCodeAt(0) === 0xfeff ? source.slice(1) : source).replace(/\r\n/g, '\n');
  const errors: YamlError[] = [];
  const positions = new Map<string, number>();

  const allLines: Line[] = text.split('\n').map((raw, i) => ({
    raw,
    content: stripComment(raw),
    indent: indentOf(raw),
    number: i + 1,
  }));

  const state: State = { lines: allLines, errors, positions };

  let start = skipBlank(state, 0);
  // Skip a leading document marker; a second one means multiple documents.
  if (start < allLines.length && (allLines[start] as Line).content.trim() === '---') {
    start = skipBlank(state, start + 1);
  }

  if (start >= allLines.length) {
    return { value: null, errors, lines: positions };
  }

  const first = allLines[start] as Line;
  const parsed = parseNode(state, start, first.indent, '');

  const after = skipBlank(state, parsed.next);
  if (after < allLines.length) {
    const marker = (allLines[after] as Line).content.trim();
    if (marker === '---') {
      errors.push({
        line: (allLines[after] as Line).number,
        message: 'multiple YAML documents in one file are not supported',
      });
    }
  }

  return { value: parsed.value, errors, lines: positions };
}

// ---------------------------------------------------------------------------
// Typed accessors
// ---------------------------------------------------------------------------

export function isMap(value: YamlValue): value is YamlMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asMap(value: YamlValue | undefined): YamlMap | null {
  return value !== undefined && isMap(value) ? value : null;
}

export function asString(value: YamlValue | undefined): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return null;
}

export function asNumber(value: YamlValue | undefined): number | null {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && /^\d+(\.\d+)?$/.test(value.trim())) return Number(value);
  return null;
}

/**
 * Coerce to an array.
 *
 * Workflow syntax accepts a scalar wherever a list is allowed — `on: push` and
 * `on: [push]` mean the same thing — so nearly every consumer needs this.
 */
export function asArray(value: YamlValue | undefined): YamlValue[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function asStringArray(value: YamlValue | undefined): string[] {
  return asArray(value).map(asString).filter((entry): entry is string => entry !== null);
}
