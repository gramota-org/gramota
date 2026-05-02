#!/usr/bin/env node
/**
 * Gramota demo CLI — entry point.
 *
 *   gramota-demo self-loop   Local Issuer → Holder → Verifier roundtrip
 *   gramota-demo eu-pid      Receive a real EU-signed PID via OID4VCI
 *   gramota-demo list        Show stored credentials
 *   gramota-demo help        Print this help
 *
 * No external CLI parsing dep — argv handling is small enough to do
 * inline. Subcommands are dispatched via a switch on argv[2].
 */

import { runSelfLoop } from "./commands/self-loop.js";
import { runEuPid } from "./commands/eu-pid.js";
import { runList } from "./commands/list.js";
import { fail } from "./ui.js";

const COMMANDS = ["self-loop", "eu-pid", "list", "help"] as const;
type Command = (typeof COMMANDS)[number];

function printHelp(): void {
  console.log("Gramota demo CLI");
  console.log("");
  console.log("Usage: gramota-demo <command>");
  console.log("");
  console.log("Commands:");
  console.log(
    "  self-loop   Local Issuer → Holder → Verifier roundtrip (no network)",
  );
  console.log(
    "  eu-pid      Receive a real EU-signed PID via OID4VCI auth-code + PAR",
  );
  console.log(
    "              (interactive: opens a browser, prompts for OOB code)",
  );
  console.log("  list        Show stored credentials");
  console.log("  help        Print this help");
  console.log("");
  console.log("Environment:");
  console.log(
    "  EUDI_DEMO_OPEN_BROWSER=0   Disable auto-open of authorization URL",
  );
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === undefined || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }
  if (!(COMMANDS as readonly string[]).includes(cmd)) {
    fail(`unknown command: ${cmd}`);
    console.log("");
    printHelp();
    process.exit(1);
  }
  switch (cmd as Command) {
    case "self-loop":
      await runSelfLoop();
      return;
    case "eu-pid":
      await runEuPid();
      return;
    case "list":
      await runList();
      return;
    case "help":
      printHelp();
      return;
  }
}

main().catch((err: unknown) => {
  fail(err instanceof Error ? err.message : String(err));
  if (err instanceof Error && err.stack !== undefined) {
    console.error(err.stack);
  }
  process.exit(1);
});
