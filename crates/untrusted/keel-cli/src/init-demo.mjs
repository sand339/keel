// Keel's first session. It runs in the V8 microVM, calls no model, and makes
// two harmless requests so you can see the trusted approval screen once
// before real work depends on it.

const say = (text) => console.log(text);

// One GET through `Keel.fetch`, which sends every request through Keel's
// egress proxy: the only way out of this machine.
async function attempt(url) {
  try {
    const response = await Keel.fetch(url);
    if (response.status === 403) return "was refused by Keel (403)";
    return `answered ${response.status}`;
  } catch (error) {
    return `could not be reached (${error?.message ?? error})`;
  }
}

say("");
say("KEEL FIRST SESSION");
say("This script is the workload. Treat what it prints as untrusted: only the");
say("screen you reach with Ctrl-] is drawn by Keel itself.");
say("");
say("1 of 2. The script now asks for https://example.com/.");
say("   Keel holds the request and shows a pending-approval notice.");
say("   Press Ctrl-], read the action, then press A to approve it once.");
const first = await attempt("https://example.com/");
say(`   Result: example.com ${first}.`);
if (first.startsWith("could not")) {
  say("   The gate is decided before any connection is made, so an approved");
  say("   request that then cannot connect (offline?) still counts.");
}
say("");
say("2 of 2. The script now asks for https://example.org/.");
say("   Press Ctrl-], then press Escape to deny it.");
const second = await attempt("https://example.org/");
say(`   Result: example.org ${second}.`);
say("   A denied request reaches the workload only as a refusal; nothing left");
say("   this machine for it.");
say("");
say("Done. Both decisions are in this session's signed audit log.");
