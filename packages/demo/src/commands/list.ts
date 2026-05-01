import { FileCredentialStore } from "../file-store.js";
import { divider, info, warn } from "../ui.js";

export async function runList(): Promise<void> {
  divider("Stored credentials");
  const store = new FileCredentialStore();
  info(`store: ${store.filePath}`);
  const all = await store.list();
  if (all.length === 0) {
    warn("none yet — run `self-loop` or `eu-pid` first");
    return;
  }
  for (const c of all) {
    console.log("");
    console.log(`  id:          ${c.id}`);
    console.log(`  issuer:      ${c.issuer}`);
    console.log(`  receivedAt:  ${new Date(c.receivedAt * 1000).toISOString()}`);
    console.log(`  disclosures: ${c.parsed.disclosures.length}`);
    const claims = c.parsed.disclosures
      .filter((d) => d.name !== null)
      .map((d) => d.name)
      .join(", ");
    console.log(`  claim names: ${claims || "<none>"}`);
  }
}
