import fs from "node:fs";

const runtime = typeof Deno === "undefined" ? "microVM" : "host sandbox";

console.log(`Keel V8 ${process.versions.v8} (${runtime})`);
console.log(`Keel SDK available: ${typeof Keel.fetch === "function"}`);
fs.writeFileSync("v8-smoke-result.txt", "vm-v8-ok\n");

try {
  fs.readFileSync("/etc/shadow");
  throw new Error("unexpected read outside the workspace");
} catch (error) {
  const accessDenied =
    error?.code === "ERR_ACCESS_DENIED" || error?.name === "NotCapable";
  if (!accessDenied) throw error;
  console.log("host-independent file restriction passed");
}
