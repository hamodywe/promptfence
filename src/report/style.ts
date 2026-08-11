/**
 * Terminal styling.
 *
 * Written by hand rather than pulled from a package: it is forty lines, it is
 * the kind of code that never changes, and the alternative is a runtime
 * dependency in a tool whose selling point is having none.
 *
 * Colour is disabled when `NO_COLOR` is set (the cross-tool convention), when
 * `FORCE_COLOR=0`, when the stream is not a TTY, or when `TERM=dumb`. Piping
 * output to a file or a CI log therefore produces clean text automatically.
 */

const CSI = '[';

const CODES = {
  reset: `${CSI}0m`,
  bold: `${CSI}1m`,
  dim: `${CSI}2m`,
  red: `${CSI}31m`,
  green: `${CSI}32m`,
  yellow: `${CSI}33m`,
  blue: `${CSI}34m`,
  magenta: `${CSI}35m`,
  cyan: `${CSI}36m`,
  grey: `${CSI}90m`,
} as const;

const ANSI_PATTERN = /\[[0-9;]*m/g;

export type StyleName = keyof typeof CODES;

export interface Styler {
  readonly enabled: boolean;
  (name: StyleName, text: string): string;
}

function detectColorSupport(stream: NodeJS.WriteStream, env: NodeJS.ProcessEnv): boolean {
  if (env['NO_COLOR'] !== undefined && env['NO_COLOR'] !== '') return false;
  if (env['FORCE_COLOR'] === '0') return false;
  if (env['FORCE_COLOR'] !== undefined && env['FORCE_COLOR'] !== '') return true;
  if (env['TERM'] === 'dumb') return false;
  return stream.isTTY === true;
}

export function createStyler(stream: NodeJS.WriteStream, env: NodeJS.ProcessEnv = process.env): Styler {
  const enabled = detectColorSupport(stream, env);

  const styler = ((name: StyleName, text: string): string =>
    enabled ? `${CODES[name]}${text}${CODES.reset}` : text) as {
      (name: StyleName, text: string): string;
      enabled: boolean;
    };

  styler.enabled = enabled;
  return styler as Styler;
}

/** Visible width of a string, ignoring ANSI escape sequences. */
export function visibleWidth(text: string): number {
  return text.replace(ANSI_PATTERN, '').length;
}

/** Pad to `width` accounting for ANSI escapes, which `String.padEnd` miscounts. */
export function padEnd(text: string, width: number): string {
  const padding = width - visibleWidth(text);
  return padding > 0 ? text + ' '.repeat(padding) : text;
}

export function padStart(text: string, width: number): string {
  const padding = width - visibleWidth(text);
  return padding > 0 ? ' '.repeat(padding) + text : text;
}

/** Truncate to `width`, appending an ellipsis when shortened. */
export function truncate(text: string, width: number): string {
  if (text.length <= width) return text;
  return width <= 1 ? text.slice(0, width) : `${text.slice(0, width - 1)}…`;
}

/**
 * A horizontal bar for score visualisation.
 *
 * Uses block-drawing characters at eighth-cell resolution so a bar of width 20
 * distinguishes 160 levels rather than 20 — enough that two skills scoring 4.01
 * and 3.98 look different, which is exactly the case the reader most needs to
 * see, because that is what an ambiguous collision looks like.
 */
const EIGHTHS = ['', '▏', '▎', '▍', '▌', '▋', '▊', '▉'] as const;

export function bar(fraction: number, width: number): string {
  const clamped = Math.max(0, Math.min(1, fraction));
  const total = clamped * width;
  let full = Math.floor(total);
  let remainder = Math.round((total - full) * 8);

  // Rounding can land on 8/8 of a cell, which is not a partial glyph but the
  // next full block. Without this promotion EIGHTHS[8] is undefined, the
  // fallback renders nothing, and the bar comes out a whole cell short of the
  // percentage its own label shows.
  if (remainder === 8) {
    full += 1;
    remainder = 0;
  }

  const filled = '█'.repeat(full) + (EIGHTHS[remainder] ?? '');
  return padEnd(filled, width);
}
