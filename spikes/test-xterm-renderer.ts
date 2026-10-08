import { Terminal } from "../.phase1/xterm/xterm-headless.mjs";

const binary = Deno.args[0];
if (!binary) throw new Error("renderer binary path is required");
const child = new Deno.Command(binary, {
  args: ["--canonical", "12", "80"],
  stdin: "piped",
  stdout: "piped",
  stderr: "piped",
}).spawn();

const messages = [
  guest(
    new TextEncoder().encode("\x1b[6n\x1b[2J\x1b[Halpha beta\r\nsecond line"),
  ),
  guest(new TextEncoder().encode("\x1b[2;")),
  guest(
    concat(new TextEncoder().encode("7Hgamma "), new Uint8Array([0xf0, 0x9f])),
  ),
  guest(new Uint8Array([0x9a, 0x80])),
  new Uint8Array([0x61, 0x6e, 0x70]),
  guest(new TextEncoder().encode("\x1b[?1000h\x1b[?1049hALT")),
  guest(new TextEncoder().encode("\x1b[?1049l\x1b[?1000lPRIMARY")),
  new Uint8Array([0x66]),
];
const writer = child.stdin.getWriter();
for (const message of messages) await writer.write(message);
await writer.close();
const output = await readAll(child.stdout);
const errors = new TextDecoder().decode(await readAll(child.stderr));
const status = await child.status;
if (!status.success) throw new Error(`renderer failed: ${errors}`);

const frames = decodeFrames(output);
const snapshots = frames.filter((frame) => frame.tag === 0x73).map((frame) =>
  frame.bytes
);
const replies = frames.filter((frame) => frame.tag === 0x69).map((frame) =>
  new TextDecoder().decode(frame.bytes)
);
if (replies.join("") !== "\x1b[1;1R") {
  throw new Error(`terminal query reply was not forwarded: ${replies}`);
}
if (snapshots.length !== 9) {
  throw new Error(`expected 9 snapshots, got ${snapshots.length}`);
}
const screens = [];
for (const snapshot of snapshots) {
  const terminal = new Terminal({
    rows: 12,
    cols: 80,
    scrollback: 0,
    allowProposedApi: true,
  });
  await new Promise<void>((resolve) => terminal.write(snapshot, resolve));
  screens.push(
    terminal.buffer.active.getLine(11)?.translateToString(true) ?? "",
  );
  terminal.dispose();
}
if (!screens[4].includes("KEEL APPROVAL PENDING")) {
  throw new Error("approval notification row was not rendered");
}
if (screens[5].includes("KEEL APPROVAL PENDING")) {
  throw new Error("approval notification row was not cleared");
}
const finalTerminal = new Terminal({
  rows: 12,
  cols: 80,
  scrollback: 0,
  allowProposedApi: true,
});
await new Promise<void>((resolve) =>
  finalTerminal.write(
    "stale edge text" +
      "Z".repeat(80 - "stale edge text".length) +
      "\x1b[?69h\x1b[3;70s\x1b[3;10r",
    resolve,
  )
);
for (const snapshot of snapshots) {
  await new Promise<void>((resolve) => finalTerminal.write(snapshot, resolve));
}
const contents = Array.from(
  { length: 12 },
  (_, row) =>
    finalTerminal.buffer.active.getLine(row)?.translateToString(true) ?? "",
).join("\n");
if (
  !contents.includes("alpha beta") ||
  !contents.includes("gamma 🚀") ||
  !contents.includes("PRIMARY") ||
  contents.includes("ALT") ||
  contents.includes("stale edge text") ||
  contents.includes("ZZZZ")
) {
  throw new Error(
    `split CSI or UTF-8 input was not reconstructed:\n${contents}`,
  );
}
if (
  finalTerminal.buffer.active.type !== "normal" ||
  finalTerminal.modes.mouseTrackingMode !== "none"
) {
  throw new Error(
    `a replayed snapshot leaked an earlier terminal mode: buffer=${finalTerminal.buffer.active.type}, mouse=${finalTerminal.modes.mouseTrackingMode}`,
  );
}
finalTerminal.dispose();
console.log(
  "xterm renderer snapshot, split-sequence, Unicode, and approval tests passed",
);

function guest(bytes: Uint8Array): Uint8Array {
  const message = new Uint8Array(5 + bytes.length);
  message[0] = 0x67;
  new DataView(message.buffer).setUint32(1, bytes.length);
  message.set(bytes, 5);
  return message;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

async function readAll(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const chunks = [];
  let length = 0;
  for await (const chunk of stream) {
    chunks.push(chunk);
    length += chunk.length;
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function decodeFrames(
  encoded: Uint8Array,
): Array<{ tag: number; bytes: Uint8Array }> {
  const frames = [];
  let offset = 0;
  while (offset < encoded.length) {
    if (encoded.length - offset < 5) {
      throw new Error("truncated renderer frame prefix");
    }
    const tag = encoded[offset];
    offset += 1;
    const length = new DataView(encoded.buffer, encoded.byteOffset + offset, 4)
      .getUint32(0);
    offset += 4;
    if (encoded.length - offset < length) throw new Error("truncated frame");
    frames.push({ tag, bytes: encoded.slice(offset, offset + length) });
    offset += length;
  }
  return frames;
}
