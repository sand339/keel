import { Terminal } from "../.phase1/xterm/xterm-headless.mjs";
import { SerializeAddon } from "../.phase1/xterm/addon-serialize.mjs";

const GUEST = 0x67;
const RESIZE = 0x72;
const REPAINT = 0x70;
const FINISH = 0x66;
const APPROVAL_PENDING = 0x61;
const APPROVAL_CLEAR = 0x6e;
const SNAPSHOT = 0x73;
const TERMINAL_REPLY = 0x69;
const MAX_GUEST_FRAME = 16 * 1024;
const MAX_SNAPSHOT = 4 * 1024 * 1024;
const encoder = new TextEncoder();

if (Deno.args.length === 1 && Deno.args[0] === "--version") {
  console.log("keel-xterm-renderer 0.0.1 (xterm-headless 6.0.0)");
  Deno.exit(0);
}
if (Deno.args.length !== 3 || Deno.args[0] !== "--canonical") {
  throw new Error("usage: keel-xterm-renderer --canonical ROWS COLUMNS");
}

let rows = boundedDimension(Deno.args[1], "rows");
let columns = boundedDimension(Deno.args[2], "columns");
const terminal = new Terminal({
  rows,
  cols: columns,
  scrollback: 0,
  allowProposedApi: true,
});
const serializer = new SerializeAddon();
terminal.loadAddon(serializer);
const terminalReplies: Uint8Array[] = [];
terminal.onData((data) => terminalReplies.push(encoder.encode(data)));
let approvalPending = false;
let input = new Uint8Array(0);
let finished = false;

for await (const chunk of Deno.stdin.readable) {
  const joined = new Uint8Array(input.length + chunk.length);
  joined.set(input);
  joined.set(chunk, input.length);
  input = joined;
  await consumeMessages();
  if (finished) break;
}
if (!finished) throw new Error("renderer input ended without a finish message");
terminal.dispose();

function boundedDimension(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1000) {
    throw new Error(`invalid terminal ${label}`);
  }
  return parsed;
}

async function consumeMessages(): Promise<void> {
  while (input.length > 0 && !finished) {
    const tag = input[0];
    if (tag === GUEST) {
      if (input.length < 5) return;
      const length = new DataView(input.buffer, input.byteOffset + 1, 4)
        .getUint32(0);
      if (length > MAX_GUEST_FRAME) {
        throw new Error("guest frame exceeds renderer limit");
      }
      if (input.length < 5 + length) return;
      const guest = input.slice(5, 5 + length);
      input = input.slice(5 + length);
      await new Promise<void>((resolve) => terminal.write(guest, resolve));
      for (const reply of terminalReplies.splice(0)) {
        await writeFrame(TERMINAL_REPLY, reply);
      }
      await emitSnapshot();
      continue;
    }
    if (tag === RESIZE) {
      if (input.length < 5) return;
      const size = new DataView(input.buffer, input.byteOffset + 1, 4);
      rows = boundedDimension(String(size.getUint16(0)), "rows");
      columns = boundedDimension(String(size.getUint16(2)), "columns");
      input = input.slice(5);
      terminal.resize(columns, rows);
      await emitSnapshot();
      continue;
    }
    input = input.slice(1);
    if (tag === REPAINT) await emitSnapshot();
    else if (tag === APPROVAL_PENDING) {
      approvalPending = true;
      await emitSnapshot();
    } else if (tag === APPROVAL_CLEAR) {
      approvalPending = false;
      await emitSnapshot();
    } else if (tag === FINISH) finished = true;
    else throw new Error("unknown renderer message");
  }
}

async function emitSnapshot(): Promise<void> {
  // SerializeAddon emits modes that are enabled, but deliberately does not
  // emit resets for modes absent from the model. Reset those modes first so
  // every frame is canonical even when replayed over a previous frame whose
  // guest used the alternate buffer, mouse tracking, or bracketed paste.
  let snapshot = "\x1b[?2026h\x1b[?1049l\x1b[?1l\x1b[?66l";
  // Ink/tmux can temporarily enable horizontal and vertical margins. ED and
  // CUP are constrained by those margins on real terminals, so clearing a
  // supposedly canonical frame without resetting both leaves old columns at
  // the edge and shifts every later snapshot. This was the source of the
  // live `Th`/`Re` margin residue and letters inserted into later words.
  snapshot += "\x1b[?69l\x1b[?6l\x1b[r";
  snapshot += "\x1b[?2004l\x1b[4l\x1b[?45l\x1b[?1004l";
  snapshot += "\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?7h";
  snapshot += "\x1b[?25h\x1b[0m\x1b[2J\x1b[H";
  snapshot += serializer.serialize({ scrollback: 0 });
  if (approvalPending) {
    const notice = "  KEEL APPROVAL PENDING - Ctrl-] or Ctrl-A /approve".slice(
      0,
      columns,
    );
    snapshot +=
      `\x1b7\x1b[${rows};1H\x1b[0m\x1b[2K\x1b[7m${notice}\x1b[0m\x1b8\x1b[?25l`;
  }
  snapshot += "\x1b[?2026l";
  const bytes = encoder.encode(snapshot);
  if (bytes.length > MAX_SNAPSHOT) {
    throw new Error("display snapshot exceeds renderer limit");
  }
  await writeFrame(SNAPSHOT, bytes);
}

async function writeFrame(tag: number, bytes: Uint8Array): Promise<void> {
  const prefix = new Uint8Array(5);
  prefix[0] = tag;
  new DataView(prefix.buffer).setUint32(1, bytes.length);
  await writeAll(prefix);
  await writeAll(bytes);
}

async function writeAll(bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    offset += await Deno.stdout.write(bytes.subarray(offset));
  }
}
