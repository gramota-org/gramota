/**
 * Minimal CLI formatting helpers — no external deps.
 *
 * Plain-ASCII by default; ANSI colors only when stdout is a TTY (so
 * piped output stays readable). Designed to be self-explanatory in
 * a transcript without a screen reader.
 */

const isTty = process.stdout.isTTY === true;
const reset = isTty ? "\x1b[0m" : "";
const bold = isTty ? "\x1b[1m" : "";
const dim = isTty ? "\x1b[2m" : "";
const green = isTty ? "\x1b[32m" : "";
const cyan = isTty ? "\x1b[36m" : "";
const yellow = isTty ? "\x1b[33m" : "";

export function divider(title: string): void {
  if (title) {
    console.log("");
    console.log(`${bold}${cyan}━━ ${title} ━━${reset}`);
  } else {
    console.log("");
  }
}

export function step(n: number, message: string): void {
  console.log("");
  console.log(`${bold}${cyan}[${n}]${reset} ${bold}${message}${reset}`);
}

export function info(message: string): void {
  console.log(`    ${dim}${message}${reset}`);
}

export function success(message: string): void {
  console.log(`${green}${bold}✓${reset} ${bold}${message}${reset}`);
}

export function warn(message: string): void {
  console.log(`${yellow}!${reset} ${message}`);
}

export function fail(message: string): void {
  console.error(
    `${isTty ? "\x1b[31m" : ""}${bold}✗ ${message}${reset}`,
  );
}
