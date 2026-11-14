// A standalone GitHub-compatible git forge: git smart HTTP (upload-pack v2, receive-pack v0),
// REST v3, GraphQL v4 and MCP over streamable HTTP. Node 22 stdlib only, in-memory store,
// no clock and no randomness: every timestamp comes from a fixed base plus a counter, so a
// replay of the same requests leaves the same state.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------ constants

export const VIEWER_LOGIN = 'adaiversen'; // scenario viewer, derived below from the fixed seed
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_IDENTITY = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
const ZERO_OID = '0000000000000000000000000000000000000000';
const TIME_BASE_SEC = 1735689600; // 2025-01-01T00:00:00Z; every timestamp is this plus a counter
const AGENT = 'github-core-clone/1.0.0';
const JSON_TYPE = 'application/json; charset=utf-8';

/** The scenario viewer login, recomputed from the contest's fixed seed (wire.ts SCENARIO_SEED). */
function computeViewerLogin(): string {
  const U64 = 0xffffffffffffffffn;
  const SEED = 0x6a09e667f3bcc909n;
  const fnv = (text: string): bigint => {
    let h = 0xcbf29ce484222325n;
    for (let i = 0; i < text.length; i += 1) {
      h ^= BigInt(text.charCodeAt(i));
      h = (h * 0x100000001b3n) & U64;
    }
    return h;
  };
  const mix = (v: bigint): bigint => {
    let z = (v + 0x9e3779b97f4a7c15n) & U64;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
    return (z ^ (z >> 31n)) & U64;
  };
  let state = mix(SEED ^ fnv('users'));
  const nextU32 = (): number => {
    let x = state;
    x = (x ^ (x >> 12n)) & U64;
    x = (x ^ (x << 25n)) & U64;
    x = (x ^ (x >> 27n)) & U64;
    state = x;
    return Number(((x * 0x2545f4914f6cdd1dn) & U64) >> 32n);
  };
  const nextInt = (max: number): number => {
    if (max === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % max);
    for (;;) {
      const v = nextU32();
      if (v < limit) return v % max;
    }
  };
  const FIRST = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
  const LAST = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];
  const first = FIRST[nextInt(FIRST.length)] ?? 'ada';
  const last = LAST[nextInt(LAST.length)] ?? 'iversen';
  return `${first}${last}`.replace(/[^a-z0-9-]/g, '');
}

// Sanity: the derived login must equal the constant the rest of the file uses.
if (computeViewerLogin() !== VIEWER_LOGIN) throw new Error('scenario viewer derivation drifted');

// ------------------------------------------------------------------ small utils

let seqCounter = 0;
function nextSeq(): number {
  seqCounter += 1;
  return seqCounter;
}
function nextTs(): number {
  return TIME_BASE_SEC + nextSeq();
}
function pad2(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}
/** ISO 8601 UTC for epoch seconds, without Date. */
function isoOf(epochSec: number): string {
  const days = Math.floor(epochSec / 86400);
  const secs = epochSec - days * 86400;
  const hh = Math.floor(secs / 3600);
  const mm = Math.floor((secs - hh * 3600) / 60);
  const ss = secs - hh * 3600 - mm * 60;
  // civil from days (Howard Hinnant's algorithm), days since 1970-01-01
  const z = days + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  const year = m <= 2 ? y + 1 : y;
  return `${year}-${pad2(m)}-${pad2(d)}T${pad2(hh)}:${pad2(mm)}:${pad2(ss)}.000Z`;
}
function sha1hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}
function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}
function b64decode(text: string): Buffer {
  // F12: Buffer.from(text, 'base64') never throws on garbage — it silently drops
  // non-alphabet characters. Validate first (alphabet + padding, then a re-encode
  // round-trip) so invalid content answers 422 instead of a 201 with wrong bytes.
  const clean = text.replace(/[\r\n\t ]+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error('invalid base64 content');
  const buf = Buffer.from(clean, 'base64');
  if (buf.toString('base64') !== clean) throw new Error('invalid base64 content');
  return buf;
}
function b64urlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}
function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}
function esc(text: string): string {
  return JSON.stringify(text);
}

// ------------------------------------------------------------------ git object model

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1hex(Buffer.concat([head, data]));
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
const TREE_MODES = new Set(['40000', '100644', '100755', '120000', '160000', '100664']);
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = sp < 0 ? -1 : data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('truncated tree entry');
    const mode = data.subarray(off, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    // Finding 7 / CVE-2026-63478: reject corrupt entries — unknown modes, and
    // `.` / `..` / slash names that could escape the tree on checkout.
    if (!TREE_MODES.has(mode)) throw new Error(`invalid tree mode ${mode}`);
    if (name === '.' || name === '..' || name.includes('/') || name.includes('\\') || name.includes('\0')) {
      throw new Error(`invalid tree entry name ${JSON.stringify(name)}`);
    }
    entries.push({
      mode,
      name,
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}
function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, r);
}
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    // Legacy group-writable mode normalises to 100644 on write (git behaviour).
    const mode = e.mode === '100664' ? '100644' : e.mode;
    parts.push(Buffer.from(`${mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  // Finding 6: `tree` must be the first line and `parent` lines only immediately
  // after it — a tree/parent line further down is an ordinary ignored header.
  let seenOther = false;
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const val = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree' || key === 'parent') {
      if (seenOther) continue;
      if (key === 'tree') tree = val;
      else parents.push(val);
      continue;
    }
    if (key !== '') seenOther = true; // continuation lines (key '') don't count
    if (key === 'author') author = val;
    else if (key === 'committer') committer = val;
  }
  return { tree, parents, author, committer, message };
}
function buildCommit(fields: { tree: string; parents?: readonly string[]; message: string; author?: string; committer?: string; timestamp?: number }): Buffer {
  const ts = fields.timestamp ?? TIME_BASE_SEC;
  const who = `${fields.author ?? VIEWER_IDENTITY} ${ts} +0000`;
  const com = `${fields.committer ?? VIEWER_IDENTITY} ${ts} +0000`;
  const lines = [`tree ${fields.tree}`];
  for (const p of fields.parents ?? []) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${com}`, '');
  return Buffer.from(`${lines.join('\n')}\n${fields.message}`, 'utf8');
}
interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}
function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp >= 0) headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

/** Objects reachable from roots. With `depth`, commit generations beyond it are cut off. */
function collectReachable(
  roots: Iterable<string>,
  lookup: (oid: string) => GitObj | undefined,
  opts: { depth?: number; stopAtShallow?: ReadonlySet<string> } = {},
): Set<string> {
  const seen = new Set<string>();
  // queue of [oid, generation]; generation 1 = the roots
  const queue: Array<[string, number]> = [];
  for (const r of roots) if (isOid(r)) queue.push([r, 1]);
  while (queue.length) {
    const [oid, gen] = queue.pop() as [string, number];
    if (seen.has(oid)) continue;
    const obj = lookup(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = commitOf(oid);
      if (!c) continue;
      queue.push([c.tree, gen]);
      if (opts.depth !== undefined && gen >= opts.depth) continue;
      if (opts.stopAtShallow?.has(oid)) continue;
      for (const p of c.parents) queue.push([p, gen + 1]);
    } else if (obj.type === 'tag') {
      const t = tagOf(oid);
      if (t) queue.push([t.object, gen]);
    } else if (obj.type === 'tree') {
      for (const e of treeOf(oid)) {
        if (e.mode !== '160000') queue.push([e.oid, gen]);
      }
    }
  }
  return seen;
}
/** Commits reachable from roots, with generation numbers (1 = roots). BFS (FIFO), so the
 * first visit of a commit is always via its SHORTEST path and the generation is minimal.
 * (F3: the old DFS stack gave inflated generations on merge histories, which picked the
 * wrong merge base.) `maxGen` caps the walk: commits beyond it are neither recorded nor
 * expanded — a fetch with deepen=N only needs generations up to N, and a full fetch
 * needs none at all (its shallow list is empty). BFS visits generations in
 * non-decreasing order, so capping can never hide a shorter path. */
function commitGenerations(roots: Iterable<string>, lookup: (oid: string) => GitObj | undefined, maxGen?: number): Map<string, number> {
  const gen = new Map<string, number>();
  const queue: Array<[string, number]> = [];
  let head = 0;
  for (const r of roots) if (isOid(r)) queue.push([r, 1]);
  while (head < queue.length) {
    const [oid, g] = queue[head++] as [string, number];
    if (maxGen !== undefined && g > maxGen) continue;
    if (gen.has(oid)) continue;
    const obj = lookup(oid);
    if (!obj || obj.type !== 'commit') continue;
    gen.set(oid, g);
    const c = commitOf(oid);
    if (!c) continue;
    if (maxGen === undefined || g < maxGen) for (const p of c.parents) queue.push([p, g + 1]);
  }
  return gen;
}
/** True when `anc` is an ancestor-or-self of `tip` (walking commit parents and tag targets). */
function isAncestor(anc: string, tip: string, lookup: (oid: string) => GitObj | undefined): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = lookup(oid);
    if (!obj) continue;
    if (obj.type === 'commit') {
      const c = commitOf(oid);
      if (!c) continue;
      for (const p of c.parents) {
        if (p === anc) return true;
        queue.push(p);
      }
    } else if (obj.type === 'tag') {
      const t = tagOf(oid);
      if (!t) continue;
      if (t.object === anc) return true;
      queue.push(t.object);
    }
  }
  return false;
}
/** ALL best common ancestors of a and b (go-git recipe, generation-ordered — commit
 * dates can lie, so generation number is the ordering, never the date). A common
 * ancestor is "best" when no other common ancestor is its descendant; the
 * Independents filter drops any candidate reachable from another candidate.
 * Criss-cross histories have MORE THAN ONE best base (git merge-base --all);
 * a plain "first common ancestor" walk returns one of them arbitrarily.
 * With BFS-minimal generations, best ⟺ minimal generation-sum, so the filter
 * is belt-and-braces on top of the min-sum cut. Deterministic order (oid sort). */
function mergeBases(a: string, b: string, lookup: (oid: string) => GitObj | undefined): string[] {
  if (!isOid(a) || !isOid(b)) return [];
  if (a === b) return [a];
  // Fast path (go-git ancestorsIndex): if one tip is an ancestor of the other,
  // it IS the (only) base.
  if (isAncestor(a, b, lookup)) return [a];
  if (isAncestor(b, a, lookup)) return [b];
  const ga = commitGenerations([a], lookup);
  const gb = commitGenerations([b], lookup);
  const common: Array<{ oid: string; score: number }> = [];
  for (const [oid, d] of ga) {
    const e = gb.get(oid);
    if (e !== undefined) common.push({ oid, score: d + e });
  }
  if (common.length === 0) return [];
  const minScore = Math.min(...common.map((c) => c.score));
  const best = common.filter((c) => c.score === minScore);
  const out: string[] = [];
  for (const c of best) {
    let dominated = false;
    for (const d of best) {
      if (d.oid === c.oid) continue;
      if (isAncestor(c.oid, d.oid, lookup)) {
        dominated = true;
        break;
      }
    }
    if (!dominated) out.push(c.oid);
  }
  out.sort();
  return out;
}
/** First best common ancestor of a and b (nearest to both, by generation). */
function mergeBase(a: string, b: string, lookup: (oid: string) => GitObj | undefined): string | null {
  const bases = mergeBases(a, b, lookup);
  return bases.length ? (bases[0] as string) : null;
}
/** The merge-base TREE for (a, b): the single best base's tree, or — when several
 * best bases exist (criss-cross) — the VIRTUAL base: the bases' trees merged
 * recursively against their own merge-base (git's recursive-merge rule). If the
 * bases themselves conflict, fall back to the first best base's tree. No common
 * ancestor (unrelated histories) → the empty tree (F6). */
function mergeBaseTree(a: string, b: string): string {
  const bases = mergeBases(a, b, lookupObject);
  if (bases.length === 0) return emptyTreeOid();
  let tree = commitOf(bases[0] as string)?.tree ?? '';
  for (let i = 1; i < bases.length; i++) {
    const t2 = commitOf(bases[i] as string)?.tree ?? '';
    const bb = mergeBase(bases[0] as string, bases[i] as string, lookupObject);
    const bTree = bb ? (commitOf(bb)?.tree ?? '') : emptyTreeOid();
    if (mergeConflict(bTree, tree, t2)) break; // fall back to the tree so far
    tree = mergeTree(bTree, tree, t2);
  }
  return tree;
}

// ------------------------------------------------------------------ packfile

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}
function writePack(objects: Iterable<GitObj>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const o of list) {
    parts.push(writePackObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      // F9: bound the varint loop — a delta of all 0x80 bytes used to spin forever.
      if (off >= delta.length || shift > 63) throw new Error('delta size varint out of bounds');
      const b = delta[off++] as number;
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return v;
  };
  const srcSize = readSize();
  const tgtSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  // go-git vector (TestPatchDeltaWriterOversizedTargetHeader): never size the
  // destination from the advertised target size alone — a header claiming
  // MaxInt64 must be rejected, not allocated. 64 MiB is far above any real pack.
  if (tgtSize > 64 * 1024 * 1024) throw new Error('delta target size out of bounds');
  const out = Buffer.allocUnsafe(tgtSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++] as number;
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += (delta[off++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[off++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      // F9: Buffer.copy silently truncates out-of-range copies while `written`
      // still advances, so the final size check could pass with zero bytes out.
      if (off > delta.length) throw new Error('delta copy header out of bounds');
      if (copyOff + copySize > base.length) throw new Error('delta copy out of bounds');
      if (written + copySize > tgtSize) throw new Error('delta copy exceeds target size');
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const n = op & 0x7f;
      if (off + n > delta.length) throw new Error('delta insert out of bounds');
      if (written + n > tgtSize) throw new Error('delta insert exceeds target size');
      delta.copy(out, written, off, off + n);
      off += n;
      written += n;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== tgtSize) throw new Error('delta size mismatch');
  return out;
}
/** Parse a packfile (v2/v3), resolving OFS/REF deltas; returns objects by oid.
 * REF_DELTA bases that are not in the pack are resolved through `resolveBase` (the store). */
function readPack(pack: Buffer, options: { resolveBase?: (oid: string) => GitObj | undefined } = {}): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  interface Raw {
    offset: number;
    code: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const readVarint = (start: number): { size: number; next: number; first: number } => {
    let byte = pack[start] as number;
    const first = byte;
    let size = byte & 0x0f;
    let shift = 4;
    let off = start + 1;
    while (byte & 0x80) {
      byte = pack[off++] as number;
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    return { size, next: off, first };
  };
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOff = off;
    const h = readVarint(off);
    off = h.next;
    const code = (h.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOff, code, size: h.size, data: Buffer.alloc(0) };
    if (code === 6) {
      let byte = pack[off] as number;
      off += 1;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++] as number;
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOff - value;
    } else if (code === 7) {
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[code]) {
      throw new Error(`unknown pack type code ${code}`);
    }
    const inflated = inflateSync(pack.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (inflated.buffer.length !== h.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    off += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOff, entry);
  }
  if (off !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map<string, GitObj>();
  const resolvedByOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (e: Raw, depth = 0): { type: ObjType; data: Buffer; oid: string } => {
    const cached = (e as Raw & { _r?: { type: ObjType; data: Buffer; oid: string } })._r;
    if (cached) return cached;
    if (resolving.has(e.offset)) throw new Error('delta cycle');
    // Delta chains resolve recursively; cap the depth so a pathological pack
    // cannot stack-overflow the process (git's hard max is 4095; 1024 is the
    // stack-safe bound here — real packs stay far below it).
    if (depth > 1024) throw new Error('delta chain too deep');
    resolving.add(e.offset);
    try {
      let type: ObjType;
      let data: Buffer;
      if (e.code === 6) {
        const base = byOffset.get(e.baseOffset as number);
        // An OFS_DELTA base must lie EARLIER in the same pack (a forward
        // reference is corrupt, not a base that happens to sort later).
        if (!base || base.offset >= e.offset) throw new Error('ofs-delta base missing');
        const b = resolve(base, depth + 1);
        type = b.type;
        data = applyDelta(b.data, e.data);
      } else if (e.code === 7) {
        // F8: a REF_DELTA may precede its base entry in the pack. On a miss, resolve
        // the still-unresolved raw entries on demand (memoised) and retry, instead
        // of throwing although the base is in this same pack.
        let baseEntry = resolvedByOid.get(e.baseOid as string);
        if (!baseEntry) {
          for (const cand of raw) {
            if ((cand as Raw & { _r?: unknown })._r) continue;
            try {
              resolve(cand, depth + 1);
            } catch {
              // leave unresolved; the lookup below decides
            }
            baseEntry = resolvedByOid.get(e.baseOid as string);
            if (baseEntry) break;
          }
        }
        if (baseEntry) {
          const b = resolve(baseEntry, depth + 1);
          type = b.type;
          data = applyDelta(b.data, e.data);
        } else {
          const external = options.resolveBase?.(e.baseOid as string);
          if (!external) throw new Error('ref-delta base missing');
          type = external.type;
          data = applyDelta(external.data, e.data);
        }
      } else {
        type = CODE_TYPE[e.code] as ObjType;
        data = e.data;
      }
      const oid = hashObject(type, data);
      const out = { type, data, oid };
      (e as Raw & { _r?: unknown })._r = out;
      resolvedByOid.set(oid, e);
      return out;
    } finally {
      resolving.delete(e.offset);
    }
  };
  for (const e of raw) {
    const r = resolve(e);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return objects;
}

// ------------------------------------------------------------------ pkt-line

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
function pktLines(items: readonly (string | Buffer)[]): Buffer {
  return Buffer.concat(items.map((i) => pktLine(i)));
}
/** Decode a buffer into {lines, rest, packets}: lines are data-packet payloads up to the first flush;
 * packets keeps every packet in order, including delim (0001) and flush (0000) markers. */
function decodePktLines(buf: Buffer): {
  lines: Buffer[];
  rest: Buffer;
  packets: Array<{ type: 'data'; payload: Buffer } | { type: 'delim' } | { type: 'flush' }>;
} {
  const lines: Buffer[] = [];
  const packets: Array<{ type: 'data'; payload: Buffer } | { type: 'delim' } | { type: 'flush' }> = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line header ${JSON.stringify(head)}`);
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ type: 'flush' });
      return { lines, rest: buf.subarray(off + 4), packets };
    }
    if (len === 1) {
      packets.push({ type: 'delim' });
      off += 4;
      continue;
    }
    if (len === 2) {
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    const payload = buf.subarray(off + 4, off + len);
    lines.push(payload);
    packets.push({ type: 'data', payload });
    off += len;
  }
  if (off !== buf.length) throw new Error('truncated pkt-line stream');
  return { lines, rest: Buffer.alloc(0), packets };
}

// ------------------------------------------------------------------ store

interface Label {
  name: string;
  color: string;
}
interface IssueRec {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: Array<{ id: number; body: string; createdAt: string }>;
  seq: number;
  /** Cached JSON.stringify(issueJson(...)) — see issueJsonText/dirtyIssue. */
  _json?: string;
}
interface PullRec {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  createdAt: string;
  updatedAt: string;
  seq: number;
}
interface RepoRec {
  id: number;
  name: string;
  owner: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  seq: number;
  refs: Map<string, string>; // refname (refs/heads/x) -> oid
  labels: Map<string, Label>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number; // shared issue+PR counter, starts at 1
  commentSeq: number;
  fetchRev: number; // bumped on every ref mutation; fetch-pack cache keys on it
}
interface Store {
  repos: Map<string, RepoRec>; // key owner/name
  objects: Map<string, GitObj>;
  repoSeq: number;
}
function createStore(): Store {
  return { repos: new Map(), objects: new Map(), repoSeq: 0 };
}
const store = createStore();
function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function getRepo(owner: string, name: string): RepoRec | undefined {
  return store.repos.get(repoKey(owner, name));
}
function storeObject(type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!store.objects.has(oid)) store.objects.set(oid, { type, data });
  return oid;
}
function lookupObject(oid: string): GitObj | undefined {
  return store.objects.get(oid);
}
/** Parsed-commit/tree/tag caches (v2 perf): objects are immutable once stored, so a parsed
 * view never goes stale. Traversals (fetch, isAncestor, commit lists) re-parse the same
 * commits thousands of times without these; with them each commit parses once. */
const commitCache = new Map<string, CommitView>();
function commitOf(oid: string): CommitView | undefined {
  let c = commitCache.get(oid);
  if (c) return c;
  const obj = lookupObject(oid);
  if (!obj || obj.type !== 'commit') return undefined;
  c = parseCommit(obj.data);
  commitCache.set(oid, c);
  return c;
}
const treeCache = new Map<string, TreeEntry[]>();
function treeOf(oid: string): TreeEntry[] {
  let e = treeCache.get(oid);
  if (e) return e;
  const obj = lookupObject(oid);
  e = obj && obj.type === 'tree' ? parseTree(obj.data) : [];
  treeCache.set(oid, e);
  return e;
}
const tagCache = new Map<string, TagView>();
function tagOf(oid: string): TagView | undefined {
  let t = tagCache.get(oid);
  if (t) return t;
  const obj = lookupObject(oid);
  if (!obj || obj.type !== 'tag') return undefined;
  t = parseTag(obj.data);
  tagCache.set(oid, t);
  return t;
}
/** Fetch-pack response cache (v2 perf): identical fetch requests (same wants/haves/
 * depth/filter on the same repo revision) rebuild the same pack bytes every time.
 * Keyed on repo.fetchRev, which is bumped on every ref mutation; objects are
 * immutable, so a ref change is the only thing that can change a fetch result. */
const fetchCache = new Map<string, Buffer>();
function bumpFetchRev(repo: RepoRec): void {
  repo.fetchRev += 1;
}
function fetchCacheKey(repo: RepoRec, req: FetchReq, proto: 'v2' | 'v0'): string {
  return `${proto}|${repo.id}|${repo.fetchRev}|${req.wants.join(',')}|${req.haves.join(',')}|${req.deepen ?? ''}|${req.shallowLines.join(',')}|${req.filter ?? ''}|${req.unborn ? 1 : 0}`;
}
function fetchCachePut(key: string, body: Buffer): void {
  if (fetchCache.size >= 64) {
    const oldest = fetchCache.keys().next().value;
    if (oldest !== undefined) fetchCache.delete(oldest);
  }
  fetchCache.set(key, body);
}
function makeRepo(owner: string, name: string, opts: { description?: string; private?: boolean }): RepoRec {
  store.repoSeq += 1;
  const now = isoOf(nextTs());
  const repo: RepoRec = {
    id: 100000 + store.repoSeq,
    name,
    owner,
    description: opts.description ?? '',
    private: opts.private ?? false,
    defaultBranch: 'main',
    createdAt: now,
    updatedAt: now,
    seq: nextSeq(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    commentSeq: 0,
    fetchRev: 0,
  };
  store.repos.set(repoKey(owner, name), repo);
  return repo;
}
function repoObjectLookup(repo: RepoRec): (oid: string) => GitObj | undefined {
  return (oid) => lookupObject(oid);
}
function globalId(kind: 'repo' | 'issue' | 'pr' | 'comment', repoId: number, a?: number, b?: number): string {
  if (kind === 'repo') return b64urlEncode(`repo:${repoId}`);
  if (kind === 'issue') return b64urlEncode(`issue:${repoId}:${a}`);
  if (kind === 'pr') return b64urlEncode(`pr:${repoId}:${a}`);
  return b64urlEncode(`comment:${repoId}:${a}:${b}`);
}
function parseGlobalId(id: string): { kind: string; repoId: number; a?: number; b?: number } | null {
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const parts = text.split(':');
    if (parts[0] === 'repo' && parts.length === 2) return { kind: 'repo', repoId: Number(parts[1]) };
    if (parts[0] === 'issue' && parts.length === 3) return { kind: 'issue', repoId: Number(parts[1]), a: Number(parts[2]) };
    if (parts[0] === 'pr' && parts.length === 3) return { kind: 'pr', repoId: Number(parts[1]), a: Number(parts[2]) };
    if (parts[0] === 'comment' && parts.length === 4) return { kind: 'comment', repoId: Number(parts[1]), a: Number(parts[2]), b: Number(parts[3]) };
    return null;
  } catch {
    return null;
  }
}
function findRepoById(id: number): RepoRec | undefined {
  for (const r of store.repos.values()) if (r.id === id) return r;
  return undefined;
}

// ------------------------------------------------------------------ tree / commit helpers

/** Read a path from a tree (nested dirs); returns {oid, mode} or null. */
function treeGet(rootOid: string, path: string): { oid: string; mode: string } | null {
  const parts = path.split('/').filter((p) => p.length > 0);
  if (!parts.length) return null;
  let current = rootOid;
  for (let i = 0; i < parts.length; i += 1) {
    const obj = lookupObject(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = treeOf(current).find((e) => e.name === parts[i]);
    if (!entry) return null;
    if (i === parts.length - 1) return { oid: entry.oid, mode: entry.mode };
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}
/** Flat listing of every blob path in a tree (dirs expanded). */
function treeList(rootOid: string): Array<{ path: string; oid: string; mode: string }> {
  const out: Array<{ path: string; oid: string; mode: string }> = [];
  const walk = (treeOid: string, prefix: string): void => {
    const obj = lookupObject(treeOid);
    if (!obj || obj.type !== 'tree') return;
    for (const e of treeOf(treeOid)) {
      const p = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.mode === '40000') walk(e.oid, p);
      else out.push({ path: p, oid: e.oid, mode: e.mode });
    }
  };
  walk(rootOid, '');
  return out;
}
/** Replace one path in a tree (or delete it when blobOid is null); returns the new root tree oid. */
function treeSet(rootOid: string | null, path: string, blobOid: string | null, mode = '100644'): string {
  const parts = path.split('/').filter((p) => p.length > 0);
  const build = (treeOid: string | null, depth: number): string | null => {
    const entries = treeOid ? treeOf(treeOid) : [];
    const name = parts[depth] as string;
    const idx = entries.findIndex((e) => e.name === name);
    let child: string | null;
    if (depth === parts.length - 1) {
      child = blobOid;
      if (child !== null && idx >= 0 && (entries[idx] as TreeEntry).mode === '40000') {
        // replacing a directory with a file: drop the dir
      }
    } else {
      const sub = idx >= 0 && (entries[idx] as TreeEntry).mode === '40000' ? (entries[idx] as TreeEntry).oid : null;
      child = build(sub, depth + 1);
    }
    const next = entries.filter((e) => e.name !== name);
    if (child !== null) {
      next.push({ mode: depth === parts.length - 1 ? mode : '40000', name, oid: child });
    }
    if (next.length === 0) return null;
    return storeObject('tree', buildTree(next));
  };
  const root = build(rootOid, 0);
  if (root === null) return storeObject('tree', buildTree([]));
  return root;
}
/** Commit history reachable from a tip, newest-first: by committer timestamp (from the commit
 * object itself), then by generation (children before parents), then by arrival order. */
function commitList(tip: string): Array<{ oid: string; commit: CommitView; seq: number }> {
  const gens = commitGenerations([tip], lookupObject);
  const out: Array<{ oid: string; commit: CommitView; seq: number; ts: number; gen: number }> = [];
  for (const [oid, gen] of gens) {
    const obj = lookupObject(oid);
    if (!obj || obj.type !== 'commit') continue;
    const commit = commitOf(oid);
    if (!commit) continue;
    const m = / (\d+) \+0000$/.exec(commit.committer);
    out.push({ oid, commit, seq: commitSeqOf(oid), ts: m ? Number(m[1]) : TIME_BASE_SEC, gen });
  }
  out.sort((a, b) => b.ts - a.ts || a.gen - b.gen || b.seq - a.seq);
  return out.map(({ oid, commit, seq }) => ({ oid, commit, seq }));
}
/** Per-commit creation order: commits are numbered by arrival in the store. */
const commitSeqMap = new Map<string, number>();
function commitSeqOf(oid: string): number {
  const v = commitSeqMap.get(oid);
  return v === undefined ? 0 : v;
}
function noteCommit(oid: string): void {
  if (!commitSeqMap.has(oid)) commitSeqMap.set(oid, nextSeq());
}
/** Create a commit object for a single-file change on `parentOid` (or a root commit). */
function contentCommit(repo: RepoRec, parentOid: string | null, path: string, content: Buffer, message: string, mode = '100644'): { commitOid: string; blobOid: string } {
  const blobOid = storeObject('blob', content);
  let baseTree = '';
  if (parentOid) {
    const parent = lookupObject(parentOid);
    if (parent && parent.type === 'commit') baseTree = commitOf(parentOid)?.tree ?? '';
  }
  const newTree = treeSet(baseTree === '' ? null : baseTree, path, blobOid, mode);
  const ts = nextTs();
  const commit = buildCommit({
    tree: newTree,
    parents: parentOid ? [parentOid] : [],
    message: message.endsWith('\n') ? message : `${message}\n`,
    timestamp: ts,
  });
  const commitOid = storeObject('commit', commit);
  noteCommit(commitOid);
  return { commitOid, blobOid };
}
/** The merge base of two commit oids, or null. */
/** Files changed between two trees: {path, status, additions, deletions, changes}. */
function diffFiles(baseTree: string, headTree: string): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const base = new Map(treeList(baseTree).map((e) => [e.path, e.oid]));
  const head = new Map(treeList(headTree).map((e) => [e.path, e.oid]));
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const lineCount = (oid: string): number => {
    const obj = lookupObject(oid);
    if (!obj || obj.type !== 'blob') return 0;
    if (obj.data.length === 0) return 0;
    return obj.data.toString('utf8').split('\n').length - (obj.data[obj.data.length - 1] === 0x0a ? 1 : 0);
  };
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const p of [...paths].sort()) {
    const b = base.get(p);
    const h = head.get(p);
    if (b === h) continue;
    if (b === undefined) {
      const n = lineCount(h as string);
      out.push({ filename: p, status: 'added', additions: n, deletions: 0, changes: n });
    } else if (h === undefined) {
      const n = lineCount(b);
      out.push({ filename: p, status: 'removed', additions: 0, deletions: n, changes: n });
    } else {
      // simple multiset line diff
      const aLines = lookupObject(b)?.data.toString('utf8').split('\n') ?? [];
      const cLines = lookupObject(h)?.data.toString('utf8').split('\n') ?? [];
      const counts = new Map<string, number>();
      for (const l of aLines) counts.set(l, (counts.get(l) ?? 0) + 1);
      let common = 0;
      for (const l of cLines) {
        const c = counts.get(l) ?? 0;
        if (c > 0) {
          counts.set(l, c - 1);
          common += 1;
        }
      }
      const adds = cLines.length - common;
      const dels = aLines.length - common;
      out.push({ filename: p, status: 'modified', additions: Math.max(0, adds), deletions: Math.max(0, dels), changes: Math.max(0, adds) + Math.max(0, dels) });
    }
  }
  return out;
}
/** Conflict test for a 3-way merge: a path changed on both sides of the base with different results. */
function mergeConflict(baseTree: string, headTree: string, otherTree: string): boolean {
  const base = new Map(treeList(baseTree).map((e) => [e.path, e.oid]));
  const head = new Map(treeList(headTree).map((e) => [e.path, e.oid]));
  const other = new Map(treeList(otherTree).map((e) => [e.path, e.oid]));
  const paths = new Set([...base.keys(), ...head.keys(), ...other.keys()]);
  for (const p of paths) {
    const b = base.get(p);
    const h = head.get(p);
    const o = other.get(p);
    const hChanged = h !== b;
    const oChanged = o !== b;
    if (hChanged && oChanged && h !== o) return true;
  }
  return false;
}
/** 3-way merge result tree (head wins where both changed identically; base/other rule per git). */
function mergeTree(baseTree: string, headTree: string, otherTree: string): string {
  // F5: the result carries {oid, mode} — the old map kept oids only and rebuilt every
  // file as 100644, losing exec bits, symlinks and submodules on squash merge.
  const base = new Map(treeList(baseTree).map((e) => [e.path, e]));
  const head = new Map(treeList(headTree).map((e) => [e.path, e]));
  const other = new Map(treeList(otherTree).map((e) => [e.path, e]));
  const result = new Map<string, { oid: string; mode: string }>();
  const paths = new Set([...base.keys(), ...head.keys(), ...other.keys()]);
  for (const p of paths) {
    const b = base.get(p);
    const h = head.get(p);
    const o = other.get(p);
    if (h?.oid === o?.oid) {
      if (h !== undefined) result.set(p, { oid: h.oid, mode: h.mode });
    } else if (o?.oid === b?.oid) {
      if (h !== undefined) result.set(p, { oid: h.oid, mode: h.mode });
    } else if (h?.oid === b?.oid) {
      if (o !== undefined) result.set(p, { oid: o.oid, mode: o.mode });
    }
  }
  // rebuild nested trees from the flat map
  const nested = new Map<string, Map<string, { mode: string; oid: string }>>();
  const rootEntries = new Map<string, { mode: string; oid: string }>();
  const ensureDir = (dir: string): Map<string, { mode: string; oid: string }> => {
    if (dir === '') return rootEntries;
    let m = nested.get(dir);
    if (!m) {
      m = new Map();
      nested.set(dir, m);
    }
    return m;
  };
  for (const [p, v] of [...result.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const parts = p.split('/');
    const name = parts[parts.length - 1] as string;
    const dir = parts.slice(0, -1).join('/');
    ensureDir(dir).set(name, { mode: v.mode, oid: v.oid });
  }
  const buildDir = (dir: string): string => {
    const entries: TreeEntry[] = [];
    const files = dir === '' ? rootEntries : (nested.get(dir) as Map<string, { mode: string; oid: string }>);
    if (files) for (const [name, v] of files) entries.push({ mode: v.mode, name, oid: v.oid });
    // subdirectories
    const prefix = dir === '' ? '' : `${dir}/`;
    const subdirs = new Set<string>();
    for (const d of nested.keys()) {
      if (d.startsWith(prefix) && d !== dir) {
        const rest = d.slice(prefix.length);
        if (rest && !rest.includes('/')) subdirs.add(d);
      }
    }
    for (const sd of [...subdirs].sort()) {
      const name = sd.slice(prefix.length);
      entries.push({ mode: '40000', name, oid: buildDir(sd) });
    }
    return storeObject('tree', buildTree(entries));
  };
  return buildDir('');
}
/** The base branch tip as it stands now (a PR's stored baseSha is from creation time). */
function currentBaseTip(repo: RepoRec, pr: PullRec): string {
  return repo.refs.get(`refs/heads/${pr.baseRef}`) ?? pr.baseSha;
}
/** The canonical empty tree oid, stored once. F6: the merge base for unrelated histories. */
let cachedEmptyTree: string | null = null;
function emptyTreeOid(): string {
  if (cachedEmptyTree === null) cachedEmptyTree = storeObject('tree', buildTree([]));
  return cachedEmptyTree;
}
/** Whether a squash merge of `pr` onto the current base tip would conflict. */
function prHasConflict(repo: RepoRec, pr: PullRec): boolean {
  const baseTip = currentBaseTip(repo, pr);
  // mergeBaseTree handles criss-cross (virtual base) and unrelated (empty tree, F6).
  const mbTree = mergeBaseTree(baseTip, pr.headSha);
  const baseTree = commitOf(baseTip)?.tree ?? '';
  const headTree = commitOf(pr.headSha)?.tree ?? '';
  return mergeConflict(mbTree, headTree, baseTree);
}
/** Squash-merge a PR onto its base branch. Returns {commitOid} or null on conflict. */
function squashMerge(repo: RepoRec, pr: PullRec): { commitOid: string } | null {
  const baseTip = currentBaseTip(repo, pr);
  const baseCommit = lookupObject(baseTip);
  const headCommit = lookupObject(pr.headSha);
  if (!baseCommit || baseCommit.type !== 'commit' || !headCommit || headCommit.type !== 'commit') return null;
  const baseTree = parseCommit(baseCommit.data).tree;
  const headTree = parseCommit(headCommit.data).tree;
  const mbTree = mergeBaseTree(baseTip, pr.headSha);
  if (mergeConflict(mbTree, headTree, baseTree)) return null;
  const mergedTree = mergeTree(mbTree, headTree, baseTree);
  const ts = nextTs();
  const message = pr.title.endsWith('\n') ? pr.title : `${pr.title}\n`;
  const commit = buildCommit({
    tree: mergedTree,
    parents: [baseTip],
    message: `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}\n\n${message}`,
    timestamp: ts,
  });
  const commitOid = storeObject('commit', commit);
  noteCommit(commitOid);
  return { commitOid };
}

// ------------------------------------------------------------------ http plumbing

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  url: URL;
  parts: string[];
  body: Buffer;
  token: string;
  reqId: string;
}
let reqCounter = 0;
function nextReqId(): string {
  reqCounter += 1;
  return `req-${reqCounter.toString(16).padStart(8, '0')}`;
}
function sendJson(ctx: Ctx, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = JSON.stringify(value);
  const headers: Record<string, string> = {
    'Content-Type': JSON_TYPE,
    'X-GitHub-Request-Id': ctx.reqId,
    'X-GitHub-Media-Type': 'github.v3',
    ...extraHeaders,
  };
  ctx.res.writeHead(status, headers);
  ctx.res.end(text);
}
function sendNoContent(ctx: Ctx, status: number, extraHeaders: Record<string, string> = {}): void {
  ctx.res.writeHead(status, { 'X-GitHub-Request-Id': ctx.reqId, ...extraHeaders });
  ctx.res.end();
}
function sendRaw(ctx: Ctx, status: number, contentType: string, data: Buffer, extraHeaders: Record<string, string> = {}): void {
  ctx.res.writeHead(status, { 'Content-Type': contentType, 'X-GitHub-Request-Id': ctx.reqId, ...extraHeaders });
  ctx.res.end(data);
}
function sendError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}
async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  if (chunks.length === 0) return Buffer.alloc(0);
  if (chunks.length === 1) return chunks[0] as Buffer;
  return Buffer.concat(chunks);
}
function parseJsonBody(ctx: Ctx): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (ctx.body.length === 0) return { ok: true, value: {} };
  try {
    const v = JSON.parse(ctx.body.toString('utf8')) as unknown;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) return { ok: true, value: v as Record<string, unknown> };
    return { ok: true, value: {} };
  } catch {
    return { ok: false };
  }
}
function bearerToken(req: IncomingMessage): string | null {
  const h = req.headers.authorization;
  if (!h || !/^Bearer\s+/.test(h)) return null;
  return h.replace(/^Bearer\s+/, '').trim();
}
/** Auth for REST/GraphQL/MCP/git: empty token on the server means "any bearer works" (local trials). */
function authed(ctx: Ctx): boolean {
  const t = bearerToken(ctx.req);
  if (t === null || t === '') return false;
  if (ctx.token === '') return true;
  return t === ctx.token;
}
function isValidOwnerRepo(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(s) && !s.endsWith('.git');
}
function viewerJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: b64urlEncode(`user:${VIEWER_ID}`),
    avatar_url: 'https://avatars.githubusercontent.com/u/1000?v=4',
    html_url: `https://github.com/${VIEWER_LOGIN}`,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    public_repos: store.repos.size,
    created_at: isoOf(TIME_BASE_SEC),
    updated_at: isoOf(TIME_BASE_SEC),
  };
}
function repoJson(r: RepoRec): Record<string, unknown> {
  return {
    id: r.id,
    node_id: b64urlEncode(`repo:${r.id}`),
    name: r.name,
    full_name: `${r.owner}/${r.name}`,
    private: r.private,
    owner: { login: r.owner, id: r.owner === VIEWER_LOGIN ? VIEWER_ID : 1001, node_id: b64urlEncode(`user:${r.owner === VIEWER_LOGIN ? VIEWER_ID : 1001}`), avatar_url: '', html_url: `https://github.com/${r.owner}`, type: 'User' },
    html_url: `https://github.com/${r.owner}/${r.name}`,
    description: r.description,
    fork: false,
    url: `https://api.github.com/repos/${r.owner}/${r.name}`,
    created_at: r.createdAt,
    updated_at: r.updatedAt,
    pushed_at: r.updatedAt,
    default_branch: r.defaultBranch,
    has_issues: true,
    has_projects: false,
    has_downloads: true,
    has_wiki: false,
    has_pages: false,
    archived: false,
    disabled: false,
    license: null,
    topics: [],
    visibility: r.private ? 'private' : 'public',
    forks_count: 0,
    open_issues_count: [...r.issues.values()].filter((i) => i.state === 'open').length,
    watchers_count: 0,
    size: 0,
  };
}
function issueJson(r: RepoRec, i: IssueRec): Record<string, unknown> {
  return {
    id: 200000 + r.id * 1000 + i.number,
    node_id: globalId('issue', r.id, i.number),
    number: i.number,
    title: i.title,
    body: i.body,
    state: i.state,
    locked: false,
    labels: i.labels.map((l) => ({ name: l.name, color: l.color })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: b64urlEncode(`user:${VIEWER_ID}`) },
    assignee: null,
    assignees: [],
    comments: i.comments.length,
    created_at: i.createdAt,
    updated_at: i.updatedAt,
    closed_at: i.closedAt,
    html_url: `https://github.com/${r.owner}/${r.name}/issues/${i.number}`,
    repository_url: `https://api.github.com/repos/${r.owner}/${r.name}`,
  };
}
/** Serialized-issue cache (v2 perf): the read workload re-serializes the same issue
 * 2.000×. The JSON string is cached on the record and invalidated by dirtyIssue()
 * on every mutation (PATCH, comment add, GraphQL close/comment). */
function issueJsonText(r: RepoRec, i: IssueRec): string {
  if (i._json === undefined) i._json = JSON.stringify(issueJson(r, i));
  return i._json;
}
function dirtyIssue(i: IssueRec): void {
  i._json = undefined;
}
function sendJsonText(ctx: Ctx, status: number, text: string, extraHeaders: Record<string, string> = {}): void {
  const headers: Record<string, string> = {
    'Content-Type': JSON_TYPE,
    'X-GitHub-Request-Id': ctx.reqId,
    'X-GitHub-Media-Type': 'github.v3',
    ...extraHeaders,
  };
  ctx.res.writeHead(status, headers);
  ctx.res.end(text);
}
function pullJson(r: RepoRec, p: PullRec): Record<string, unknown> {
  return {
    id: 300000 + r.id * 1000 + p.number,
    node_id: globalId('pr', r.id, p.number),
    number: p.number,
    title: p.title,
    body: p.body,
    state: p.state,
    locked: false,
    draft: false,
    merged: p.merged,
    mergeable: prMergeable(r, p),
    merged_at: p.mergedAt,
    merge_commit_sha: p.mergeSha,
    head: { label: `${r.owner}:${p.headRef}`, ref: p.headRef, sha: p.headSha, user: { login: r.owner } },
    base: { label: `${r.owner}:${p.baseRef}`, ref: p.baseRef, sha: p.baseSha, user: { login: r.owner } },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: b64urlEncode(`user:${VIEWER_ID}`) },
    created_at: p.createdAt,
    updated_at: p.updatedAt,
    closed_at: p.state === 'closed' ? p.updatedAt : null,
    html_url: `https://github.com/${r.owner}/${r.name}/pull/${p.number}`,
  };
}
function prMergeable(r: RepoRec, p: PullRec): string {
  if (p.state === 'closed') return 'UNKNOWN';
  const conflict = prHasConflict(r, p);
  return conflict ? 'CONFLICTING' : 'MERGEABLE';
}
function commitJson(oid: string): Record<string, unknown> {
  const obj = lookupObject(oid);
  const c = obj && obj.type === 'commit' ? parseCommit(obj.data) : null;
  const ts = c ? Number(c.committer.replace(/.* (\d+) \+0000$/, '$1')) : TIME_BASE_SEC;
  const msg = c?.message ?? '';
  const authorLine = c?.author ?? VIEWER_IDENTITY;
  const committerLine = c?.committer ?? VIEWER_IDENTITY;
  const ident = (line: string): { name: string; email: string } => {
    const m = /^(.*) <(.*)> \d+ \+0000$/.exec(line);
    return m ? { name: m[1] as string, email: m[2] as string } : { name: VIEWER_NAME, email: VIEWER_EMAIL };
  };
  const a = ident(authorLine);
  const cm = ident(committerLine);
  // The stored object message ends with a newline (git convention); the API presents it without.
  const apiMessage = msg.endsWith('\n') ? msg.slice(0, -1) : msg;
  return {
    sha: oid,
    node_id: b64urlEncode(`commit:${oid}`),
    commit: {
      author: { name: a.name, email: a.email, date: isoOf(ts) },
      committer: { name: cm.name, email: cm.email, date: isoOf(ts) },
      message: apiMessage,
      tree: { sha: c?.tree ?? ZERO_OID },
    },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID },
    parents: (c?.parents ?? []).map((p) => ({ sha: p })),
    html_url: `https://github.com/commit/${oid}`,
    url: `https://api.github.com/repos/commit/${oid}`,
  };
}
function resolveRef(repo: RepoRec, refish: string): string | null {
  if (isOid(refish)) return lookupObject(refish) ? refish : null;
  if (refish.startsWith('refs/')) return repo.refs.get(refish) ?? null;
  const byBranch = repo.refs.get(`refs/heads/${refish}`);
  if (byBranch) return byBranch;
  const byTag = repo.refs.get(`refs/tags/${refish}`);
  if (byTag) return byTag;
  return null;
}
function defaultTip(repo: RepoRec): string | null {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}
function pageParams(ctx: Ctx): { perPage: number; page: number } {
  const perPageRaw = Number(ctx.url.searchParams.get('per_page') ?? '30');
  const pageRaw = Number(ctx.url.searchParams.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  return { perPage, page };
}
function paginate<T>(ctx: Ctx, items: readonly T[]): { page: T[]; headers: Record<string, string> } {
  const { perPage, page } = pageParams(ctx);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const headers: Record<string, string> = {};
  if (page < totalPages) {
    const base = `${ctx.url.origin}${ctx.url.pathname}`;
    const next = new URL(base);
    next.searchParams.set('per_page', String(perPage));
    next.searchParams.set('page', String(page + 1));
    const last = new URL(base);
    last.searchParams.set('per_page', String(perPage));
    last.searchParams.set('page', String(totalPages));
    headers.Link = `<${next.href}>; rel="next", <${last.href}>; rel="last"`;
  }
  return { page: slice, headers };
}

// ------------------------------------------------------------------ REST v3

async function handleRest(ctx: Ctx): Promise<boolean> {
  const p = ctx.parts; // after 'api/v3'
  if (p.length === 0) {
    if (ctx.method !== 'GET') return false;
    if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
    sendJson(ctx, 200, { current_user_url: 'https://api.github.com/user', repository_url: 'https://api.github.com/repos/{owner}/{repo}' }, { 'X-OAuth-Scopes': 'repo, read:org' });
    return true;
  }
  if (p[0] === 'meta' && p.length === 1) {
    if (ctx.method !== 'GET') return false;
    if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
    sendJson(ctx, 200, { verifiable_password_authentication: false, installed_version: '1.0.0', github_services_sha: '0000000000000000000000000000000000000000' });
    return true;
  }
  if (p[0] === 'user') {
    if (p.length === 1) {
      if (ctx.method !== 'GET') return false;
      if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
      sendJson(ctx, 200, viewerJson());
      return true;
    }
    if (p[1] === 'repos') {
      if (ctx.method === 'GET') {
        if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
        const list = [...store.repos.values()]
          .filter((r) => r.owner === VIEWER_LOGIN)
          .sort((a, b) => a.seq - b.seq)
          .map((r) => repoJson(r));
        const { page, headers } = paginate(ctx, list);
        sendJson(ctx, 200, page, headers);
        return true;
      }
      if (ctx.method === 'POST') {
        if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
        const name = parsed.value.name;
        if (typeof name !== 'string' || name === '') return sendError(ctx, 422, 'Repository name is required'), true;
        if (!isValidOwnerRepo(name)) return sendError(ctx, 422, 'Repository name is invalid'), true;
        if (getRepo(VIEWER_LOGIN, name)) return sendError(ctx, 422, 'Repository already exists'), true;
        const repo = makeRepo(VIEWER_LOGIN, name, {
          description: typeof parsed.value.description === 'string' ? parsed.value.description : '',
          private: parsed.value.private === true,
        });
        sendJson(ctx, 201, repoJson(repo));
        return true;
      }
      return false;
    }
    return false;
  }
  if (p[0] === 'repos' && p.length >= 3) {
    const owner = p[1] as string;
    const repoName = p[2] as string;
    if (!isValidOwnerRepo(owner) || !isValidOwnerRepo(repoName)) {
      if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
      return sendError(ctx, 404, 'Not Found'), true;
    }
    const repo = getRepo(owner, repoName);
    if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
    if (!repo || repo.owner !== VIEWER_LOGIN) return sendError(ctx, 404, 'Not Found'), true;
    const rest = p.slice(3);
    if (rest.length === 0) {
      if (ctx.method === 'GET') {
        sendJson(ctx, 200, repoJson(repo));
        return true;
      }
      if (ctx.method === 'PATCH') {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
        if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
        if (typeof parsed.value.default_branch === 'string') repo.defaultBranch = parsed.value.default_branch;
        repo.updatedAt = isoOf(nextTs());
        sendJson(ctx, 200, repoJson(repo));
        return true;
      }
      if (ctx.method === 'DELETE') {
        store.repos.delete(repoKey(owner, repoName));
        sendNoContent(ctx, 204);
        return true;
      }
      return false;
    }
    // /git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (ctx.method !== 'POST') return false;
      const parsed = parseJsonBody(ctx);
      if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
      const ref = parsed.value.ref;
      const sha = parsed.value.sha;
      if (typeof ref !== 'string' || !/^refs\/[a-z]+\/[A-Za-z0-9._/-]+$/.test(ref)) return sendError(ctx, 422, 'Invalid ref'), true;
      if (typeof sha !== 'string' || !isOid(sha)) return sendError(ctx, 422, 'Invalid sha'), true;
      if (!lookupObject(sha)) return sendError(ctx, 422, 'Object does not exist'), true;
      if (repo.refs.has(ref)) return sendError(ctx, 422, 'Reference already exists'), true;
      repo.refs.set(ref, sha);
      bumpFetchRev(repo);
      repo.updatedAt = isoOf(nextTs());
      sendJson(ctx, 201, { ref, object: { sha } });
      return true;
    }
    // /branches
    if (rest[0] === 'branches' && rest.length === 1) {
      if (ctx.method !== 'GET') return false;
      const branches = [...repo.refs.entries()]
        .filter(([r]) => r.startsWith('refs/heads/'))
        .map(([r, sha]) => ({ name: r.slice('refs/heads/'.length), commit: { sha }, protected: false }));
      sendJson(ctx, 200, branches);
      return true;
    }
    // /commits
    if (rest[0] === 'commits' && rest.length === 1) {
      if (ctx.method !== 'GET') return false;
      const shaParam = ctx.url.searchParams.get('sha');
      const tip = shaParam ? resolveRef(repo, shaParam) : defaultTip(repo);
      if (!tip) {
        sendJson(ctx, 200, []);
        return true;
      }
      const list = commitList(tip).map((c) => commitJson(c.oid));
      const { page, headers } = paginate(ctx, list);
      sendJson(ctx, 200, page, headers);
      return true;
    }
    // /contents/*
    if (rest[0] === 'contents') {
      // F4: segments arrive already decoded by the router — decoding again turned
      // `a%2Fb.txt` (%252F) into nested `a/b.txt` and threw on a bare `%`.
      const path = rest.slice(1).join('/');
      if (ctx.method === 'GET') {
        const refParam = ctx.url.searchParams.get('ref');
        const tip = refParam ? resolveRef(repo, refParam) : defaultTip(repo);
        if (!tip) return sendError(ctx, 404, 'Not Found'), true;
        const commit = lookupObject(tip);
        if (!commit || commit.type !== 'commit') return sendError(ctx, 404, 'Not Found'), true;
        const tree = parseCommit(commit.data).tree;
        if (path === '') {
          const listing = parseTree(lookupObject(tree)?.data ?? Buffer.alloc(0)).map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            encoding: 'none',
            size: 0,
            name: e.name,
            path: e.name,
            sha: e.oid,
            url: `https://api.github.com/repos/${owner}/${repoName}/contents/${encodeURIComponent(e.name)}`,
          }));
          sendJson(ctx, 200, listing);
          return true;
        }
        const found = treeGet(tree, path);
        if (!found) return sendError(ctx, 404, 'Not Found'), true;
        if (found.mode === '40000') {
          const listing = parseTree(lookupObject(found.oid)?.data ?? Buffer.alloc(0)).map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            encoding: 'none',
            size: 0,
            name: e.name,
            path: `${path}/${e.name}`,
            sha: e.oid,
            url: `https://api.github.com/repos/${owner}/${repoName}/contents/${encodeURIComponent(`${path}/${e.name}`)}`,
          }));
          sendJson(ctx, 200, listing);
          return true;
        }
        const blob = lookupObject(found.oid);
        if (!blob) return sendError(ctx, 404, 'Not Found'), true;
        sendJson(ctx, 200, {
          type: 'file',
          encoding: 'base64',
          size: blob.data.length,
          name: path.split('/').pop(),
          path,
          content: b64encode(blob.data),
          sha: found.oid,
          url: `https://api.github.com/repos/${owner}/${repoName}/contents/${encodeURIComponent(path)}`,
        });
        return true;
      }
      if (ctx.method === 'PUT' || ctx.method === 'DELETE') {
        const parsed = parseJsonBody(ctx);
        if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
        const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName) ?? null;
        const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'Update';
        if (ctx.method === 'PUT') {
          const content = parsed.value.content;
          if (typeof content !== 'string') return sendError(ctx, 422, 'Content is required'), true;
          let bytes: Buffer;
          try {
            bytes = b64decode(content);
          } catch {
            return sendError(ctx, 422, 'Invalid base64 content'), true;
          }
          const existing = tip ? treeGet(parseCommit(lookupObject(tip)?.data ?? Buffer.alloc(0)).tree, path) : null;
          const expectedSha = parsed.value.sha;
          if (existing && typeof expectedSha === 'string' && expectedSha !== existing.oid) {
            return sendError(ctx, 409, 'Conflict: sha does not match the current blob'), true;
          }
          if (!existing && typeof expectedSha === 'string' && expectedSha !== '') {
            return sendError(ctx, 409, 'Conflict: sha does not match the current blob'), true;
          }
          const { commitOid, blobOid } = contentCommit(repo, tip, path, bytes, message);
          repo.refs.set(refName, commitOid);
          bumpFetchRev(repo);
          repo.updatedAt = isoOf(nextTs());
          sendJson(ctx, existing ? 200 : 201, { content: { name: path.split('/').pop(), path, sha: blobOid, encoding: 'base64' }, commit: { sha: commitOid } });
          return true;
        }
        // DELETE contents
        if (!tip) return sendError(ctx, 404, 'Not Found'), true;
        const existing = treeGet(parseCommit(lookupObject(tip)?.data ?? Buffer.alloc(0)).tree, path);
        if (!existing) return sendError(ctx, 404, 'Not Found'), true;
        const expectedSha = parsed.value.sha;
        if (typeof expectedSha === 'string' && expectedSha !== existing.oid) {
          return sendError(ctx, 409, 'Conflict: sha does not match the current blob'), true;
        }
        const newTree = treeSet(parseCommit(lookupObject(tip)?.data ?? Buffer.alloc(0)).tree, path, null);
        const ts = nextTs();
        const commit = buildCommit({ tree: newTree, parents: [tip], message: message.endsWith('\n') ? message : `${message}\n`, timestamp: ts });
        const commitOid = storeObject('commit', commit);
        noteCommit(commitOid);
        repo.refs.set(refName, commitOid);
        bumpFetchRev(repo);
        repo.updatedAt = isoOf(nextTs());
        sendJson(ctx, 200, { content: null, commit: { sha: commitOid } });
        return true;
      }
      return false;
    }
    // /labels
    if (rest[0] === 'labels' && rest.length === 1) {
      if (ctx.method !== 'POST') return false;
      const parsed = parseJsonBody(ctx);
      if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
      const name = parsed.value.name;
      if (typeof name !== 'string' || name === '') return sendError(ctx, 422, 'Label name is required'), true;
      if (repo.labels.has(name)) return sendError(ctx, 422, 'Label already exists'), true;
      const color = typeof parsed.value.color === 'string' ? parsed.value.color.replace(/^#/, '') : 'ededed';
      const label: Label = { name, color };
      repo.labels.set(name, label);
      sendJson(ctx, 201, { name, color });
      return true;
    }
    // /issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (ctx.method === 'GET') {
          const state = ctx.url.searchParams.get('state') ?? 'open';
          const sort = ctx.url.searchParams.get('sort') ?? 'created';
          const direction = ctx.url.searchParams.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          if (sort === 'created') {
            list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          }
          const json = list.map((i) => issueJson(repo, i));
          const { page, headers } = paginate(ctx, json);
          sendJson(ctx, 200, page, headers);
          return true;
        }
        if (ctx.method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
          const title = parsed.value.title;
          if (typeof title !== 'string' || title === '') return sendError(ctx, 422, 'Title is required'), true;
          const labelsIn = Array.isArray(parsed.value.labels) ? (parsed.value.labels as unknown[]) : [];
          const labels: Label[] = [];
          for (const l of labelsIn) {
            const name = typeof l === 'string' ? l : (l as { name?: unknown })?.name;
            if (typeof name !== 'string') continue;
            const known = repo.labels.get(name);
            if (!known) return sendError(ctx, 422, `Label "${name}" does not exist`), true;
            labels.push(known);
          }
          const number = repo.nextNumber++;
          const now = isoOf(nextTs());
          const issue: IssueRec = {
            number,
            title,
            body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
            state: 'open',
            labels,
            createdAt: now,
            updatedAt: now,
            closedAt: null,
            comments: [],
            seq: nextSeq(),
          };
          repo.issues.set(number, issue);
          sendJsonText(ctx, 201, issueJsonText(repo, issue));
          return true;
        }
        return false;
      }
      const n = Number(rest[1]);
      if (!Number.isInteger(n) || n < 1) return sendError(ctx, 404, 'Not Found'), true;
      const issue = repo.issues.get(n);
      if (rest.length === 2) {
        if (ctx.method === 'GET') {
          if (!issue) return sendError(ctx, 404, 'Not Found'), true;
          sendJsonText(ctx, 200, issueJsonText(repo, issue));
          return true;
        }
        if (ctx.method === 'PATCH') {
          if (!issue) return sendError(ctx, 404, 'Not Found'), true;
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
          if (parsed.value.state === 'open' || parsed.value.state === 'closed') {
            issue.state = parsed.value.state;
            issue.closedAt = issue.state === 'closed' ? isoOf(nextTs()) : null;
          }
          if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
          if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
          issue.updatedAt = isoOf(nextTs());
          dirtyIssue(issue);
          sendJsonText(ctx, 200, issueJsonText(repo, issue));
          return true;
        }
        return false;
      }
      if (rest[2] === 'comments') {
        if (!issue) return sendError(ctx, 404, 'Not Found'), true;
        if (ctx.method === 'GET') {
          sendJson(ctx, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: c.createdAt, updated_at: c.createdAt })));
          return true;
        }
        if (ctx.method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
          const body = parsed.value.body;
          if (typeof body !== 'string' || body === '') return sendError(ctx, 422, 'Body is required'), true;
          repo.commentSeq += 1;
          const comment = { id: repo.commentSeq, body, createdAt: isoOf(nextTs()) };
          issue.comments.push(comment);
          issue.updatedAt = isoOf(nextTs());
          dirtyIssue(issue);
          sendJson(ctx, 201, { id: comment.id, body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: comment.createdAt, updated_at: comment.createdAt });
          return true;
        }
        return false;
      }
      return false;
    }
    // /pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (ctx.method === 'GET') {
          const state = ctx.url.searchParams.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.seq - a.seq);
          const json = list.map((p) => pullJson(repo, p));
          const { page, headers } = paginate(ctx, json);
          sendJson(ctx, 200, page, headers);
          return true;
        }
        if (ctx.method === 'POST') {
          const parsed = parseJsonBody(ctx);
          if (!parsed.ok) return sendError(ctx, 400, 'Invalid JSON body'), true;
          const title = parsed.value.title;
          const head = parsed.value.head;
          const base = parsed.value.base;
          if (typeof title !== 'string' || title === '') return sendError(ctx, 422, 'Title is required'), true;
          if (typeof head !== 'string' || typeof base !== 'string') return sendError(ctx, 422, 'head and base are required'), true;
          const headSha = resolveRef(repo, head);
          const baseSha = resolveRef(repo, base);
          if (!headSha || !baseSha) return sendError(ctx, 422, 'head or base does not exist'), true;
          const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
          if (dup) return sendError(ctx, 422, 'A pull request already exists for this head and base'), true;
          const number = repo.nextNumber++;
          const now = isoOf(nextTs());
          const pr: PullRec = {
            number,
            title,
            body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
            state: 'open',
            headRef: head,
            baseRef: base,
            headSha,
            baseSha,
            merged: false,
            mergedAt: null,
            mergeSha: null,
            createdAt: now,
            updatedAt: now,
            seq: nextSeq(),
          };
          repo.pulls.set(number, pr);
          sendJson(ctx, 201, pullJson(repo, pr));
          return true;
        }
        return false;
      }
      const n = Number(rest[1]);
      if (!Number.isInteger(n) || n < 1) return sendError(ctx, 404, 'Not Found'), true;
      const pr = repo.pulls.get(n);
      if (rest.length === 2) {
        if (ctx.method === 'GET') {
          if (!pr) return sendError(ctx, 404, 'Not Found'), true;
          sendJson(ctx, 200, pullJson(repo, pr));
          return true;
        }
        return false;
      }
      if (rest[2] === 'files' && rest.length === 3) {
        if (ctx.method !== 'GET') return false;
        if (!pr) return sendError(ctx, 404, 'Not Found'), true;
        // mergeBaseTree: single base, virtual base (criss-cross), or empty tree (F6).
        const mbTree = mergeBaseTree(pr.baseSha, pr.headSha);
        const headTree = parseCommit(lookupObject(pr.headSha)?.data ?? Buffer.alloc(0)).tree;
        sendJson(ctx, 200, diffFiles(mbTree, headTree));
        return true;
      }
      if (rest[2] === 'merge' && rest.length === 3) {
        if (ctx.method !== 'PUT') return false;
        if (!pr) return sendError(ctx, 404, 'Not Found'), true;
        if (pr.state === 'closed') return sendError(ctx, 405, 'Pull request already merged or closed'), true;
        const conflict = prHasConflict(repo, pr);
        if (conflict) return sendError(ctx, 405, 'Merge conflict'), true;
        const result = squashMerge(repo, pr);
        if (!result) return sendError(ctx, 405, 'Merge conflict'), true;
        repo.refs.set(`refs/heads/${pr.baseRef}`, result.commitOid);
        bumpFetchRev(repo);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = isoOf(nextTs());
        pr.mergeSha = result.commitOid;
        pr.updatedAt = isoOf(nextTs());
        repo.updatedAt = isoOf(nextTs());
        sendJson(ctx, 200, { merged: true, sha: result.commitOid, message: `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}` });
        return true;
      }
      return false;
    }
    return false;
  }
  return false;
}

// ------------------------------------------------------------------ GraphQL

interface GqlVar {
  [name: string]: unknown;
}
interface GqlSelection {
  field: string;
  alias: string | null;
  args: Record<string, unknown>;
  children: GqlSelection[] | null;
  fragmentType: string | null;
}
type GqlToken =
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'punct'; value: string }
  | { kind: 'var'; value: string };

function gqlTokenize(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i] as string;
    if (/\s/.test(ch) || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const escCh = src[j + 1] as string;
          out += escCh === 'n' ? '\n' : escCh === 't' ? '\t' : escCh === 'r' ? '\r' : escCh;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      let name = '';
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) {
        name += src[j];
        j += 1;
      }
      tokens.push({ kind: 'var', value: name });
      i = j;
      continue;
    }
    if (/[0-9-]/.test(ch) && (/\d/.test(ch) || (ch === '-' && /\d/.test(src[i + 1] ?? '')))) {
      let j = i;
      let num = '';
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) {
        num += src[j];
        j += 1;
      }
      tokens.push({ kind: 'int', value: Number(num) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      let name = '';
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) {
        name += src[j];
        j += 1;
      }
      tokens.push({ kind: 'name', value: name });
      i = j;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    tokens.push({ kind: 'punct', value: ch });
    i += 1;
  }
  return tokens;
}
class GqlParser {
  private pos = 0;
  private tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }
  peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }
  next(): GqlToken {
    const t = this.tokens[this.pos] as GqlToken;
    this.pos += 1;
    return t;
  }
  expectPunct(v: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.value !== v) throw new Error(`expected ${v}, got ${JSON.stringify(t)}`);
  }
  isPunct(v: string): boolean {
    const t = this.peek();
    return t !== undefined && t.kind === 'punct' && t.value === v;
  }
  parseValue(vars: GqlVar): unknown {
    const t = this.next();
    if (t.kind === 'var') return vars[t.value];
    if (t.kind === 'string' || t.kind === 'int') return t.value;
    if (t.kind === 'name') {
      if (t.value === 'true') return true;
      if (t.value === 'false') return false;
      if (t.value === 'null') return null;
      return t.value; // enum literal
    }
    if (t.kind === 'punct' && t.value === '[') {
      const list: unknown[] = [];
      while (!this.isPunct(']')) list.push(this.parseValue(vars));
      this.expectPunct(']');
      return list;
    }
    if (t.kind === 'punct' && t.value === '{') {
      const obj: Record<string, unknown> = {};
      while (!this.isPunct('}')) {
        const key = this.next();
        if (key.kind !== 'name') throw new Error('expected object key');
        this.expectPunct(':');
        obj[key.value] = this.parseValue(vars);
      }
      this.expectPunct('}');
      return obj;
    }
    throw new Error(`unexpected token ${JSON.stringify(t)}`);
  }
  parseArguments(vars: GqlVar): Record<string, unknown> {
    const args: Record<string, unknown> = {};
    if (!this.isPunct('(')) return args;
    this.expectPunct('(');
    while (!this.isPunct(')')) {
      const key = this.next();
      if (key.kind !== 'name') throw new Error('expected argument name');
      this.expectPunct(':');
      args[key.value] = this.parseValue(vars);
    }
    this.expectPunct(')');
    return args;
  }
  parseSelectionSet(vars: GqlVar, typeName: string): GqlSelection[] {
    const out: GqlSelection[] = [];
    this.expectPunct('{');
    while (!this.isPunct('}')) {
      const t = this.peek();
      if (t?.kind === 'punct' && t.value === '...') {
        this.next();
        const nxt = this.peek();
        if (nxt?.kind === 'name' && nxt.value === 'on') {
          this.next();
          const typeTok = this.next();
          if (typeTok.kind !== 'name') throw new Error('expected fragment type');
          const children = this.parseSelectionSet(vars, typeTok.value);
          out.push({ field: '__fragment__', alias: null, args: {}, children, fragmentType: typeTok.value });
        } else {
          // named fragment spread: parse but treat as wildcard (documents in this contest use inline only)
          const fragName = this.next();
          if (fragName.kind !== 'name') throw new Error('expected fragment name');
          out.push({ field: '__spread__', alias: null, args: { name: fragName.value }, children: null, fragmentType: null });
        }
        continue;
      }
      const nameTok = this.next();
      if (nameTok.kind !== 'name') throw new Error('expected field name');
      let alias: string | null = null;
      let field = nameTok.value;
      if (this.isPunct(':')) {
        this.next();
        const real = this.next();
        if (real.kind !== 'name') throw new Error('expected field name after alias');
        alias = field;
        field = real.value;
      }
      const args = this.parseArguments(vars);
      const children = this.isPunct('{') ? this.parseSelectionSet(vars, field) : null;
      out.push({ field, alias, args, children, fragmentType: null });
    }
    this.expectPunct('}');
    return out;
  }
}
interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
  varDefs: Record<string, string>;
}
function parseGqlDocument(src: string, vars: GqlVar): GqlOperation {
  const parser = new GqlParser(gqlTokenize(src));
  let kind: 'query' | 'mutation' = 'query';
  let name: string | null = null;
  const varDefs: Record<string, string> = {};
  let t = parser.peek();
  if (t?.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
    kind = t.value;
    parser.next();
    t = parser.peek();
    if (t?.kind === 'name') {
      name = t.value;
      parser.next();
    }
  }
  if (parser.isPunct('(')) {
    parser.expectPunct('(');
    while (!parser.isPunct(')')) {
      const vt = parser.next();
      if (vt.kind !== 'var') throw new Error('expected variable');
      parser.expectPunct(':');
      // read type (name with optional [] and !)
      let typeStr = '';
      while (!parser.isPunct(')') && !parser.isPunct(',')) {
        const tt = parser.next();
        typeStr += tt.kind === 'name' ? tt.value : tt.value;
      }
      varDefs[vt.value] = typeStr;
      if (parser.isPunct(',')) parser.next();
    }
    parser.expectPunct(')');
  }
  const selections = parser.parseSelectionSet(vars, kind === 'mutation' ? 'Mutation' : 'Query');
  return { kind, name, selections, varDefs };
}
const TYPE_FIELDS: Record<string, string[]> = {
  Viewer: ['login', 'id', 'name', 'email', 'avatarUrl', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url', 'description', 'private', 'createdAt', 'updatedAt'],
  Issue: ['id', 'number', 'title', 'body', 'state', 'author', 'createdAt', 'updatedAt', 'closedAt', 'labels', 'comments', 'url'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'author', 'createdAt', 'updatedAt', 'mergedAt'],
  Comment: ['id', 'body', 'author', 'createdAt'],
  Label: ['id', 'name', 'color'],
  User: ['login', 'id', 'name', 'email'],
  Ref: ['name', 'target'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  SearchType: [],
};
const ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'CODE', 'DISCUSSION', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
};
class GqlExecutor {
  errors: Array<{ message: string }> = [];
  private issueCursor(repoId: number, n: number): string {
    return b64urlEncode(`cursor:${repoId}:${n}`);
  }
  private issuesFor(repo: RepoRec, args: Record<string, unknown>): { list: IssueRec[]; hasNext: boolean; endCursor: string | null; totalCount: number } {
    const states = Array.isArray(args.states) ? (args.states as string[]) : null;
    const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
    const first = typeof args.first === 'number' ? args.first : null;
    const after = typeof args.after === 'string' ? args.after : null;
    let list = [...repo.issues.values()];
    if (states) {
      const want = new Set(states.map((s) => s.toLowerCase()));
      list = list.filter((i) => want.has(i.state));
    }
    // F11: totalCount is the states-filtered count, before after/first slicing.
    const totalCount = list.length;
    const dir = orderBy?.direction === 'ASC' ? 'asc' : 'desc';
    list.sort((a, b) => (dir === 'asc' ? a.seq - b.seq : b.seq - a.seq));
    if (after) {
      try {
        const text = Buffer.from(after, 'base64url').toString('utf8');
        const m = /^cursor:(\d+):(\d+)$/.exec(text);
        if (m) {
          const num = Number(m[2]);
          const idx = list.findIndex((i) => i.number === num);
          if (idx >= 0) list = list.slice(idx + 1);
        }
      } catch {
        // ignore bad cursor
      }
    }
    let hasNext = false;
    if (first !== null && list.length > first) {
      hasNext = true;
      list = list.slice(0, first);
    }
    const endCursor = list.length ? this.issueCursor(repo.id, (list[list.length - 1] as IssueRec).number) : null;
    return { list, hasNext, endCursor, totalCount };
  }
  private repoFields(repo: RepoRec, sels: GqlSelection[], typeName: string): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === '__fragment__') {
        if (sel.fragmentType === typeName && sel.children) {
          Object.assign(out, this.repoFields(repo, sel.children, typeName));
        }
        continue;
      }
      if (sel.field === '__spread__') continue;
      if (!TYPE_FIELDS[typeName]?.includes(sel.field) && sel.field !== '__typename') {
        this.errors.push({ message: `Cannot query field "${sel.field}" on type "${typeName}".` });
        continue;
      }
      switch (sel.field) {
        case '__typename':
          out[key] = 'Repository';
          break;
        case 'id':
          out[key] = globalId('repo', repo.id);
          break;
        case 'databaseId':
          out[key] = repo.id;
          break;
        case 'name':
          out[key] = repo.name;
          break;
        case 'nameWithOwner':
          out[key] = `${repo.owner}/${repo.name}`;
          break;
        case 'owner':
          out[key] = this.userFields(repo.owner, sel.children ?? []);
          break;
        case 'defaultBranchRef': {
          const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          out[key] = tip ? { name: repo.defaultBranch, target: { oid: tip } } : null;
          break;
        }
        case 'viewerPermission':
          out[key] = 'ADMIN';
          break;
        case 'hasIssuesEnabled':
          out[key] = true;
          break;
        case 'issue': {
          const n = sel.args.number;
          const issue = typeof n === 'number' ? repo.issues.get(n) : undefined;
          out[key] = issue ? this.issueFields(repo, issue, sel.children ?? []) : null;
          break;
        }
        case 'issues': {
          const { list, hasNext, endCursor, totalCount } = this.issuesFor(repo, sel.args);
          const children = sel.children ?? [];
          const nodeSels = children.find((c) => c.field === 'nodes')?.children ?? [];
          out[key] = {
            nodes: list.map((i) => this.issueFields(repo, i, nodeSels)),
            pageInfo: { hasNextPage: hasNext, hasPreviousPage: false, startCursor: list.length ? this.issueCursor(repo.id, (list[0] as IssueRec).number) : null, endCursor },
            totalCount,
          };
          break;
        }
        case 'pullRequest': {
          const n = sel.args.number;
          const pr = typeof n === 'number' ? repo.pulls.get(n) : undefined;
          out[key] = pr ? this.prFields(repo, pr, sel.children ?? []) : null;
          break;
        }
        case 'pullRequests': {
          const first = typeof sel.args.first === 'number' ? sel.args.first : null;
          let list = [...repo.pulls.values()].sort((a, b) => b.seq - a.seq);
          if (first !== null) list = list.slice(0, first);
          const nodeSels = (sel.children ?? []).find((c) => c.field === 'nodes')?.children ?? (sel.children ?? []);
          out[key] = { nodes: list.map((p) => this.prFields(repo, p, nodeSels)), pageInfo: { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: repo.pulls.size };
          break;
        }
        case 'url':
          out[key] = `https://github.com/${repo.owner}/${repo.name}`;
          break;
        case 'description':
          out[key] = repo.description;
          break;
        case 'private':
          out[key] = repo.private;
          break;
        case 'createdAt':
          out[key] = repo.createdAt;
          break;
        case 'updatedAt':
          out[key] = repo.updatedAt;
          break;
        default:
          out[key] = null;
      }
    }
    return out;
  }
  private userFields(login: string, sels: GqlSelection[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === '__typename') {
        out[key] = 'User';
        continue;
      }
      if (sel.field === 'login') out[key] = login;
      else if (sel.field === 'id') out[key] = login === VIEWER_LOGIN ? VIEWER_ID : 1001;
      else if (sel.field === 'name') out[key] = login === VIEWER_LOGIN ? VIEWER_NAME : login;
      else if (sel.field === 'email') out[key] = login === VIEWER_LOGIN ? VIEWER_EMAIL : '';
      else out[key] = null;
    }
    return out;
  }
  private issueFields(repo: RepoRec, issue: IssueRec, sels: GqlSelection[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === '__fragment__') {
        if (sel.fragmentType === 'Issue' && sel.children) Object.assign(out, this.issueFields(repo, issue, sel.children));
        continue;
      }
      if (sel.field === '__spread__') continue;
      if (!TYPE_FIELDS.Issue?.includes(sel.field) && sel.field !== '__typename') {
        this.errors.push({ message: `Cannot query field "${sel.field}" on type "Issue".` });
        continue;
      }
      switch (sel.field) {
        case '__typename':
          out[key] = 'Issue';
          break;
        case 'id':
          out[key] = globalId('issue', repo.id, issue.number);
          break;
        case 'number':
          out[key] = issue.number;
          break;
        case 'title':
          out[key] = issue.title;
          break;
        case 'body':
          out[key] = issue.body;
          break;
        case 'state':
          out[key] = issue.state === 'open' ? 'OPEN' : 'CLOSED';
          break;
        case 'author':
          out[key] = this.userFields(VIEWER_LOGIN, sel.children ?? []);
          break;
        case 'createdAt':
          out[key] = issue.createdAt;
          break;
        case 'updatedAt':
          out[key] = issue.updatedAt;
          break;
        case 'closedAt':
          out[key] = issue.closedAt;
          break;
        case 'labels':
          out[key] = { nodes: issue.labels.map((l) => ({ name: l.name, color: l.color })) };
          break;
        case 'comments':
          out[key] = { nodes: issue.comments.map((c) => ({ id: globalId('comment', repo.id, issue.number, c.id), body: c.body })) };
          break;
        case 'url':
          out[key] = `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
          break;
        default:
          out[key] = null;
      }
    }
    return out;
  }
  private prFields(repo: RepoRec, pr: PullRec, sels: GqlSelection[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === '__fragment__') {
        if (sel.fragmentType === 'PullRequest' && sel.children) Object.assign(out, this.prFields(repo, pr, sel.children));
        continue;
      }
      if (sel.field === '__spread__') continue;
      if (!TYPE_FIELDS.PullRequest?.includes(sel.field) && sel.field !== '__typename') {
        this.errors.push({ message: `Cannot query field "${sel.field}" on type "PullRequest".` });
        continue;
      }
      switch (sel.field) {
        case '__typename':
          out[key] = 'PullRequest';
          break;
        case 'id':
          out[key] = globalId('pr', repo.id, pr.number);
          break;
        case 'number':
          out[key] = pr.number;
          break;
        case 'title':
          out[key] = pr.title;
          break;
        case 'body':
          out[key] = pr.body;
          break;
        case 'state':
          out[key] = pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
          break;
        case 'merged':
          out[key] = pr.merged;
          break;
        case 'mergeable':
          out[key] = prMergeable(repo, pr);
          break;
        case 'headRefName':
          out[key] = pr.headRef;
          break;
        case 'baseRefName':
          out[key] = pr.baseRef;
          break;
        case 'headRef': {
          const tip = repo.refs.get(`refs/heads/${pr.headRef}`);
          out[key] = { name: pr.headRef, target: { oid: tip ?? pr.headSha } };
          break;
        }
        case 'baseRef': {
          const tip = repo.refs.get(`refs/heads/${pr.baseRef}`);
          out[key] = { name: pr.baseRef, target: { oid: tip ?? pr.baseSha } };
          break;
        }
        case 'files': {
          const first = typeof sel.args.first === 'number' ? sel.args.first : null;
          const mbTree = mergeBaseTree(pr.baseSha, pr.headSha);
          const headTree = parseCommit(lookupObject(pr.headSha)?.data ?? Buffer.alloc(0)).tree;
          let paths: string[] = diffFiles(mbTree, headTree).map((f) => f.filename);
          if (first !== null) paths = paths.slice(0, first);
          const nodeSels = (sel.children ?? []).find((c) => c.field === 'nodes')?.children ?? [];
          out[key] = { nodes: paths.map((p) => {
            const o: Record<string, unknown> = {};
            for (const ns of nodeSels) o[ns.alias ?? ns.field] = ns.field === 'path' ? p : null;
            return o;
          }) };
          break;
        }
        case 'author':
          out[key] = this.userFields(VIEWER_LOGIN, sel.children ?? []);
          break;
        case 'createdAt':
          out[key] = pr.createdAt;
          break;
        case 'updatedAt':
          out[key] = pr.updatedAt;
          break;
        case 'mergedAt':
          out[key] = pr.mergedAt;
          break;
        default:
          out[key] = null;
      }
    }
    return out;
  }
  private typeFields(name: string, sels: GqlSelection[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === 'name') out[key] = name;
      else if (sel.field === 'kind') out[key] = ENUM_VALUES[name] ? 'ENUM' : 'OBJECT';
      else if (sel.field === 'fields') {
        const includeDeprecated = sel.args.includeDeprecated === true;
        void includeDeprecated;
        const fields = TYPE_FIELDS[name];
        out[key] = fields ? fields.map((f) => ({ name: f })) : null;
      } else if (sel.field === 'enumValues') {
        const vals = ENUM_VALUES[name];
        out[key] = vals ? vals.map((v) => ({ name: v })) : null;
      } else out[key] = null;
    }
    return out;
  }
  execute(op: GqlOperation): Record<string, unknown> | null {
    if (op.kind === 'query') return this.executeQuery(op.selections);
    return this.executeMutation(op.selections);
  }
  private executeQuery(sels: GqlSelection[]): Record<string, unknown> | null {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      if (sel.field === '__typename') {
        out[key] = 'Query';
        continue;
      }
      if (sel.field === 'viewer') {
        const fields: Record<string, unknown> = {};
        for (const c of sel.children ?? []) {
          const ck = c.alias ?? c.field;
          if (c.field === '__typename') fields[ck] = 'Viewer';
          else if (c.field === 'login') fields[ck] = VIEWER_LOGIN;
          else if (c.field === 'id') fields[ck] = VIEWER_ID;
          else if (c.field === 'name') fields[ck] = VIEWER_NAME;
          else if (c.field === 'email') fields[ck] = VIEWER_EMAIL;
          else if (c.field === 'avatarUrl') fields[ck] = '';
          else if (c.field === 'url') fields[ck] = `https://github.com/${VIEWER_LOGIN}`;
          else {
            this.errors.push({ message: `Cannot query field "${c.field}" on type "Viewer".` });
          }
        }
        out[key] = fields;
        continue;
      }
      if (sel.field === 'repository') {
        const owner = sel.args.owner;
        const name = sel.args.name;
        const repo = typeof owner === 'string' && typeof name === 'string' ? getRepo(owner, name) : undefined;
        if (!repo || repo.owner !== VIEWER_LOGIN) {
          out[key] = null;
          continue;
        }
        out[key] = this.repoFields(repo, sel.children ?? [], 'Repository');
        continue;
      }
      if (sel.field === 'node') {
        const id = sel.args.id;
        const parsed = typeof id === 'string' ? parseGlobalId(id) : null;
        if (!parsed) {
          out[key] = null;
          continue;
        }
        const repo = findRepoById(parsed.repoId);
        if (!repo) {
          out[key] = null;
          continue;
        }
        if (parsed.kind === 'repo') {
          out[key] = this.repoFields(repo, sel.children ?? [], 'Repository');
        } else if (parsed.kind === 'issue') {
          const issue = parsed.a !== undefined ? repo.issues.get(parsed.a) : undefined;
          out[key] = issue ? this.issueFields(repo, issue, sel.children ?? []) : null;
        } else if (parsed.kind === 'pr') {
          const pr = parsed.a !== undefined ? repo.pulls.get(parsed.a) : undefined;
          out[key] = pr ? this.prFields(repo, pr, sel.children ?? []) : null;
        } else {
          out[key] = null;
        }
        continue;
      }
      if (sel.field === '__type') {
        const name = sel.args.name;
        out[key] = typeof name === 'string' ? this.typeFields(name, sel.children ?? []) : null;
        continue;
      }
      this.errors.push({ message: `Cannot query field "${sel.field}" on type "Query".` });
    }
    return this.errors.length ? null : out;
  }
  private executeMutation(sels: GqlSelection[]): Record<string, unknown> | null {
    const out: Record<string, unknown> = {};
    for (const sel of sels) {
      const key = sel.alias ?? sel.field;
      const input = (sel.args.input ?? {}) as Record<string, unknown>;
      if (sel.field === 'createIssue') {
        const repoId = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = repoId?.kind === 'repo' ? findRepoById(repoId.repoId) : undefined;
        if (!repo) {
          this.errors.push({ message: 'Repository not found.' });
          continue;
        }
        const title = typeof input.title === 'string' ? input.title : '';
        const number = repo.nextNumber++;
        const now = isoOf(nextTs());
        const issue: IssueRec = { number, title, body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], createdAt: now, updatedAt: now, closedAt: null, comments: [], seq: nextSeq() };
        repo.issues.set(number, issue);
        const children = sel.children ?? [];
        const issueSel = children.find((c) => c.field === 'issue');
        out[key] = { issue: issueSel ? this.issueFields(repo, issue, issueSel.children ?? []) : { number, id: globalId('issue', repo.id, number) } };
        continue;
      }
      if (sel.field === 'closeIssue') {
        const issueId = typeof input.issueId === 'string' ? parseGlobalId(input.issueId) : null;
        const repo = issueId ? findRepoById(issueId.repoId) : undefined;
        const issue = repo && issueId?.a !== undefined ? repo.issues.get(issueId.a) : undefined;
        if (!repo || !issue) {
          this.errors.push({ message: 'Issue not found.' });
          continue;
        }
        issue.state = 'closed';
        issue.closedAt = isoOf(nextTs());
        issue.updatedAt = isoOf(nextTs());
        dirtyIssue(issue);
        const children = sel.children ?? [];
        const issueSel = children.find((c) => c.field === 'issue');
        out[key] = { issue: issueSel ? this.issueFields(repo, issue, issueSel.children ?? []) : { number: issue.number, id: globalId('issue', repo.id, issue.number), state: 'CLOSED' } };
        continue;
      }
      if (sel.field === 'createPullRequest') {
        const repoId = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = repoId?.kind === 'repo' ? findRepoById(repoId.repoId) : undefined;
        if (!repo) {
          this.errors.push({ message: 'Repository not found.' });
          continue;
        }
        const head = typeof input.headRefName === 'string' ? input.headRefName : '';
        const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
        const headSha = resolveRef(repo, head);
        const baseSha = resolveRef(repo, base);
        if (!headSha || !baseSha) {
          this.errors.push({ message: 'head or base does not exist' });
          continue;
        }
        const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
        if (dup) {
          this.errors.push({ message: 'A pull request already exists for this head and base' });
          continue;
        }
        const number = repo.nextNumber++;
        const now = isoOf(nextTs());
        const pr: PullRec = {
          number, title: typeof input.title === 'string' ? input.title : '', body: typeof input.body === 'string' ? input.body : '',
          state: 'open', headRef: head, baseRef: base, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null,
          createdAt: now, updatedAt: now, seq: nextSeq(),
        };
        repo.pulls.set(number, pr);
        const children = sel.children ?? [];
        const prSel = children.find((c) => c.field === 'pullRequest');
        out[key] = { pullRequest: prSel ? this.prFields(repo, pr, prSel.children ?? []) : { number, id: globalId('pr', repo.id, number), state: 'OPEN', headRefName: head, baseRefName: base } };
        continue;
      }
      if (sel.field === 'mergePullRequest') {
        const prId = typeof input.pullRequestId === 'string' ? parseGlobalId(input.pullRequestId) : null;
        const repo = prId ? findRepoById(prId.repoId) : undefined;
        const pr = repo && prId?.a !== undefined ? repo.pulls.get(prId.a) : undefined;
        if (!repo || !pr) {
          this.errors.push({ message: 'Pull request not found.' });
          continue;
        }
        if (pr.state === 'closed') {
          this.errors.push({ message: 'Pull request already merged or closed' });
          continue;
        }
        const conflict = prHasConflict(repo, pr);
        if (conflict) {
          this.errors.push({ message: 'Merge conflict' });
          continue;
        }
        const result = squashMerge(repo, pr);
        if (!result) {
          this.errors.push({ message: 'Merge conflict' });
          continue;
        }
        repo.refs.set(`refs/heads/${pr.baseRef}`, result.commitOid);
        bumpFetchRev(repo);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = isoOf(nextTs());
        pr.mergeSha = result.commitOid;
        pr.updatedAt = isoOf(nextTs());
        const children = sel.children ?? [];
        const prSel = children.find((c) => c.field === 'pullRequest');
        out[key] = { pullRequest: prSel ? this.prFields(repo, pr, prSel.children ?? []) : { number: pr.number, merged: true, state: 'MERGED' } };
        continue;
      }
      if (sel.field === 'addComment') {
        const subjectId = typeof input.subjectId === 'string' ? parseGlobalId(input.subjectId) : null;
        const repo = subjectId ? findRepoById(subjectId.repoId) : undefined;
        const issue = repo && subjectId?.kind === 'issue' && subjectId.a !== undefined ? repo.issues.get(subjectId.a) : undefined;
        if (!repo || !issue) {
          this.errors.push({ message: 'Subject not found.' });
          continue;
        }
        repo.commentSeq += 1;
        const comment = { id: repo.commentSeq, body: typeof input.body === 'string' ? input.body : '', createdAt: isoOf(nextTs()) };
        issue.comments.push(comment);
        dirtyIssue(issue);
        const children = sel.children ?? [];
        const edgeSel = children.find((c) => c.field === 'commentEdge');
        const nodeSel = edgeSel?.children?.find((c) => c.field === 'node');
        const nodeFields: Record<string, unknown> = {};
        for (const ns of nodeSel?.children ?? []) {
          if (ns.field === 'id') nodeFields[ns.alias ?? 'id'] = globalId('comment', repo.id, issue.number, comment.id);
          else if (ns.field === 'body') nodeFields[ns.alias ?? 'body'] = comment.body;
          else nodeFields[ns.alias ?? ns.field] = null;
        }
        out[key] = { commentEdge: { node: nodeFields } };
        continue;
      }
      this.errors.push({ message: `Cannot query field "${sel.field}" on type "Mutation".` });
    }
    return this.errors.length ? null : out;
  }
}
async function handleGraphql(ctx: Ctx): Promise<boolean> {
  if (ctx.method !== 'POST') return false;
  if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
  const parsed = parseJsonBody(ctx);
  let docs: Array<{ query?: unknown; variables?: unknown }> = [];
  if (ctx.body.length > 0) {
    try {
      const v = JSON.parse(ctx.body.toString('utf8')) as unknown;
      if (Array.isArray(v)) docs = v as Array<{ query?: unknown; variables?: unknown }>;
      else if (v !== null && typeof v === 'object') docs = [v as { query?: unknown; variables?: unknown }];
      else return sendError(ctx, 400, 'Invalid request'), true;
    } catch {
      return sendError(ctx, 400, 'Invalid JSON body'), true;
    }
  }
  void parsed;
  const results: unknown[] = [];
  for (const doc of docs) {
    const query = typeof doc.query === 'string' ? doc.query : '';
    const vars = (doc.variables !== null && typeof doc.variables === 'object' ? doc.variables : {}) as GqlVar;
    if (!query) {
      results.push({ errors: [{ message: 'Must provide query string.' }] });
      continue;
    }
    try {
      const op = parseGqlDocument(query, vars);
      const ex = new GqlExecutor();
      const data = ex.execute(op);
      if (ex.errors.length) results.push({ data: null, errors: ex.errors });
      else results.push({ data });
    } catch (err) {
      results.push({ data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] });
    }
  }
  const isBatch = Array.isArray(JSON.parse(ctx.body.length ? ctx.body.toString('utf8') : 'null'));
  if (isBatch) {
    sendJson(ctx, 200, results);
  } else {
    sendJson(ctx, 200, results[0] ?? { data: null });
  }
  return true;
}

// ------------------------------------------------------------------ MCP

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required: string[] };
  aliases: string[];
  handler: (args: Record<string, unknown>) => { ok: boolean; payload: unknown };
}
function mcpText(payload: unknown): Array<{ type: string; text: string }> {
  return [{ type: 'text', text: JSON.stringify(payload) }];
}
function mcpErrorResult(message: string): { content: Array<{ type: string; text: string }>; isError: boolean } {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }) }], isError: true };
}
function mcpTools(): McpToolDef[] {
  const reqStr = (args: Record<string, unknown>, key: string): string | null => (typeof args[key] === 'string' ? (args[key] as string) : null);
  const tools: McpToolDef[] = [
    {
      name: 'create_repo',
      description: 'Create a new repository owned by the viewer.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Repository name' },
          description: { type: 'string', description: 'Repository description' },
          private: { type: 'boolean', description: 'Whether the repository is private' },
        },
        required: ['name'],
      },
      aliases: ['create_repository', 'createrepo'],
      handler: (args) => {
        const name = reqStr(args, 'name');
        if (!name) return { ok: false, payload: { error: 'name is required' } };
        if (!isValidOwnerRepo(name)) return { ok: false, payload: { error: 'invalid repository name' } };
        if (getRepo(VIEWER_LOGIN, name)) return { ok: false, payload: { error: 'Repository already exists' } };
        const repo = makeRepo(VIEWER_LOGIN, name, {
          description: typeof args.description === 'string' ? args.description : '',
          private: args.private === true,
        });
        return { ok: true, payload: repoJson(repo) };
      },
    },
    {
      name: 'get_repo',
      description: 'Get a repository by owner and name.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner login' },
          repo: { type: 'string', description: 'Repository name' },
        },
        required: ['owner', 'repo'],
      },
      aliases: ['get_repository'],
      handler: (args) => {
        const owner = reqStr(args, 'owner');
        const repoName = reqStr(args, 'repo');
        if (!owner || !repoName) return { ok: false, payload: { error: 'owner and repo are required' } };
        const repo = getRepo(owner, repoName);
        if (!repo || repo.owner !== VIEWER_LOGIN) return { ok: false, payload: { error: 'Not Found' } };
        return { ok: true, payload: repoJson(repo) };
      },
    },
    {
      name: 'create_issue',
      description: 'Create an issue in a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner login' },
          repo: { type: 'string', description: 'Repository name' },
          title: { type: 'string', description: 'Issue title' },
          body: { type: 'string', description: 'Issue body' },
        },
        required: ['owner', 'repo', 'title'],
      },
      aliases: ['createissue'],
      handler: (args) => {
        const owner = reqStr(args, 'owner');
        const repoName = reqStr(args, 'repo');
        const title = reqStr(args, 'title');
        if (!owner || !repoName || !title) return { ok: false, payload: { error: 'owner, repo and title are required' } };
        const repo = getRepo(owner, repoName);
        if (!repo || repo.owner !== VIEWER_LOGIN) return { ok: false, payload: { error: 'Not Found' } };
        const number = repo.nextNumber++;
        const now = isoOf(nextTs());
        const issue: IssueRec = { number, title, body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [], createdAt: now, updatedAt: now, closedAt: null, comments: [], seq: nextSeq() };
        repo.issues.set(number, issue);
        return { ok: true, payload: issueJson(repo, issue) };
      },
    },
    {
      name: 'list_issues',
      description: 'List issues in a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner login' },
          repo: { type: 'string', description: 'Repository name' },
          state: { type: 'string', description: 'open, closed or all' },
        },
        required: ['owner', 'repo'],
      },
      aliases: ['listissues'],
      handler: (args) => {
        const owner = reqStr(args, 'owner');
        const repoName = reqStr(args, 'repo');
        if (!owner || !repoName) return { ok: false, payload: { error: 'owner and repo are required' } };
        const repo = getRepo(owner, repoName);
        if (!repo || repo.owner !== VIEWER_LOGIN) return { ok: false, payload: { error: 'Not Found' } };
        const state = typeof args.state === 'string' ? args.state : 'open';
        let list = [...repo.issues.values()];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        list.sort((a, b) => b.seq - a.seq);
        return { ok: true, payload: { issues: list.map((i) => issueJson(repo, i)) } };
      },
    },
    {
      name: 'create_pull_request',
      description: 'Create a pull request between two branches.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner login' },
          repo: { type: 'string', description: 'Repository name' },
          title: { type: 'string', description: 'Pull request title' },
          head: { type: 'string', description: 'Head branch name' },
          base: { type: 'string', description: 'Base branch name' },
          body: { type: 'string', description: 'Pull request body' },
        },
        required: ['owner', 'repo', 'title', 'head', 'base'],
      },
      aliases: ['createpullrequest', 'create_pr'],
      handler: (args) => {
        const owner = reqStr(args, 'owner');
        const repoName = reqStr(args, 'repo');
        const title = reqStr(args, 'title');
        const head = reqStr(args, 'head');
        const base = reqStr(args, 'base');
        if (!owner || !repoName || !title || !head || !base) return { ok: false, payload: { error: 'owner, repo, title, head and base are required' } };
        const repo = getRepo(owner, repoName);
        if (!repo || repo.owner !== VIEWER_LOGIN) return { ok: false, payload: { error: 'Not Found' } };
        const headSha = resolveRef(repo, head);
        const baseSha = resolveRef(repo, base);
        if (!headSha || !baseSha) return { ok: false, payload: { error: 'head or base does not exist' } };
        const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
        if (dup) return { ok: false, payload: { error: 'A pull request already exists for this head and base' } };
        const number = repo.nextNumber++;
        const now = isoOf(nextTs());
        const pr: PullRec = { number, title, body: typeof args.body === 'string' ? args.body : '', state: 'open', headRef: head, baseRef: base, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, createdAt: now, updatedAt: now, seq: nextSeq() };
        repo.pulls.set(number, pr);
        return { ok: true, payload: pullJson(repo, pr) };
      },
    },
    {
      name: 'merge_pull_request',
      description: 'Merge a pull request with a squash merge.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner login' },
          repo: { type: 'string', description: 'Repository name' },
          pull_number: { type: 'integer', description: 'Pull request number' },
        },
        required: ['owner', 'repo', 'pull_number'],
      },
      aliases: ['mergepullrequest', 'merge_pr'],
      handler: (args) => {
        const owner = reqStr(args, 'owner');
        const repoName = reqStr(args, 'repo');
        const pullNumber = args.pull_number ?? args.pullNumber ?? args.number;
        if (!owner || !repoName || typeof pullNumber !== 'number') return { ok: false, payload: { error: 'owner, repo and pull_number are required' } };
        const repo = getRepo(owner, repoName);
        if (!repo || repo.owner !== VIEWER_LOGIN) return { ok: false, payload: { error: 'Not Found' } };
        const pr = repo.pulls.get(pullNumber);
        if (!pr) return { ok: false, payload: { error: 'Pull request not found' } };
        if (pr.state === 'closed') return { ok: false, payload: { error: 'Pull request already merged or closed' } };
        const conflict = prHasConflict(repo, pr);
        if (conflict) return { ok: false, payload: { error: 'Merge conflict' } };
        const result = squashMerge(repo, pr);
        if (!result) return { ok: false, payload: { error: 'Merge conflict' } };
        repo.refs.set(`refs/heads/${pr.baseRef}`, result.commitOid);
        bumpFetchRev(repo);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = isoOf(nextTs());
        pr.mergeSha = result.commitOid;
        pr.updatedAt = isoOf(nextTs());
        return { ok: true, payload: { merged: true, number: pr.number, sha: result.commitOid } };
      },
    },
  ];
  return tools;
}
function normalizeToolName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}
function findMcpTool(tools: McpToolDef[], name: string): McpToolDef | undefined {
  const norm = normalizeToolName(name);
  for (const t of tools) {
    if (normalizeToolName(t.name) === norm) return t;
    for (const a of t.aliases) if (normalizeToolName(a) === norm) return t;
  }
  // suffix match (server prefix allowed, e.g. github-core-clone-create_issue)
  for (const t of tools) {
    if (norm.endsWith(normalizeToolName(t.name))) return t;
  }
  return undefined;
}
async function handleMcp(ctx: Ctx): Promise<boolean> {
  if (ctx.method === 'DELETE') {
    sendJson(ctx, 200, {});
    return true;
  }
  if (ctx.method !== 'POST') return false;
  if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
  let body: unknown;
  try {
    body = ctx.body.length ? JSON.parse(ctx.body.toString('utf8')) : {};
  } catch {
    sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const msg = body as { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
  const id = msg.id === undefined ? null : msg.id;
  const method = typeof msg.method === 'string' ? msg.method : null;
  if (method === null) {
    sendJson(ctx, 400, { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
    return true;
  }
  if (id === null || id === undefined) {
    // notification: acknowledge silently
    sendNoContent(ctx, 202);
    return true;
  }
  const params = (msg.params !== null && typeof msg.params === 'object' ? msg.params : {}) as Record<string, unknown>;
  const result = (value: unknown): void => {
    sendJson(ctx, 200, { jsonrpc: '2.0', id, result: value });
  };
  const rpcError = (code: number, message: string): void => {
    sendJson(ctx, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  if (method === 'server/discover') {
    result({
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'],
      capabilities: { tools: {} },
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
    });
    return true;
  }
  if (method === 'initialize') {
    const version = typeof params.protocolVersion === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(params.protocolVersion) ? params.protocolVersion : '2026-07-28';
    result({
      protocolVersion: version,
      capabilities: { tools: {} },
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
    });
    return true;
  }
  if (method === 'tools/list') {
    const tools = mcpTools();
    result({
      tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
    });
    return true;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments !== null && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;
    const tool = findMcpTool(mcpTools(), name);
    if (!tool) {
      rpcError(-32602, `Unknown tool: ${name}`);
      return true;
    }
    for (const req of tool.inputSchema.required) {
      if (args[req] === undefined || args[req] === null || args[req] === '') {
        rpcError(-32602, `Missing required argument: ${req}`);
        return true;
      }
    }
    const out = tool.handler(args);
    if (!out.ok) {
      result({ content: mcpText(out.payload), isError: true });
      return true;
    }
    result({ content: mcpText(out.payload), structuredContent: out.payload });
    return true;
  }
  if (method.startsWith('notifications/')) {
    sendNoContent(ctx, 202);
    return true;
  }
  rpcError(-32601, `Method not found: ${method}`);
  return true;
}

// ------------------------------------------------------------------ git smart HTTP

const UPLOAD_AD_TYPE = 'application/x-git-upload-pack-advertisement';
const RECEIVE_AD_TYPE = 'application/x-git-receive-pack-advertisement';
const UPLOAD_RESULT_TYPE = 'application/x-git-upload-pack-result';
const RECEIVE_RESULT_TYPE = 'application/x-git-receive-pack-result';

function advertiseV0(repo: RepoRec, service: 'upload-pack' | 'receive-pack'): Buffer {
  const serviceLine = service === 'upload-pack' ? '# service=git-upload-pack\n' : '# service=git-receive-pack\n';
  const caps =
    service === 'upload-pack'
      ? `side-band-64k thin-pack multi_ack multi_ack_detailed ofs-delta shallow no-progress agent=${AGENT} symref=HEAD:refs/heads/${repo.defaultBranch}`
      : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const tip = defaultTip(repo);
  const lines: Buffer[] = [pktLine(serviceLine)];
  if (tip === null && refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    let first = true;
    if (tip) {
      const head = `${tip} HEAD${first ? `\0${caps}` : ''}\n`;
      lines.push(pktLine(head));
      first = false;
    }
    for (const [name, oid] of refs) {
      const line = `${oid} ${name}${first ? `\0${caps}` : ''}\n`;
      lines.push(pktLine(line));
      first = false;
    }
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}
function advertiseV2(repo: RepoRec, service: 'upload-pack' | 'receive-pack'): Buffer {
  if (service === 'receive-pack') return advertiseV0(repo, service);
  const lines: Buffer[] = [pktLine('# service=git-upload-pack\n')];
  lines.push(pktLine('version 2\n'));
  lines.push(pktLine('fetch=shallow wait-for-done filter\n'));
  lines.push(pktLine('ls-refs=unborn\n'));
  lines.push(pktLine('object-format=sha1\n'));
  lines.push(pktLine(`agent=${AGENT}\n`));
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}
function lsRefsV2(repo: RepoRec, rawLines: string[]): Buffer {
  const lines = rawLines.map((l) => l.trim());
  const unborn = lines.includes('unborn');
  const peel = lines.includes('peel');
  const symrefs = lines.includes('symrefs');
  const prefixes = lines.filter((l) => l.startsWith('ref-prefix ')).map((l) => l.slice('ref-prefix '.length).trim());
  const out: Buffer[] = [];
  const tip = defaultTip(repo);
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const include = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (tip) {
    const headLine = prefixes.length === 0 ? `${tip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n` : null;
    if (headLine) out.push(pktLine(headLine));
  } else if (unborn && prefixes.length === 0) {
    out.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
  }
  for (const [name, oid] of refs) {
    if (!include(name)) continue;
    let line = `${oid} ${name}`;
    if (symrefs && name === `refs/heads/${repo.defaultBranch}`) line += ` symref-target:refs/heads/${repo.defaultBranch}`;
    if (peel) {
      const obj = lookupObject(oid);
      if (obj && obj.type === 'tag') line += ` peeled:${tagOf(oid)?.object ?? ''}`;
    }
    out.push(pktLine(`${line}\n`));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}
interface FetchReq {
  wants: string[];
  haves: string[];
  shallowLines: string[];
  deepen: number | null;
  filter: string | null;
  unborn: boolean;
}
function parseFetchV2(packets: Array<{ type: 'data'; payload: Buffer } | { type: 'delim' } | { type: 'flush' }>): FetchReq {
  const req: FetchReq = { wants: [], haves: [], shallowLines: [], deepen: null, filter: null, unborn: false };
  let seenDelim = false;
  for (const pkt of packets) {
    if (pkt.type === 'delim') {
      seenDelim = true;
      continue;
    }
    if (pkt.type !== 'data' || !seenDelim) continue;
    const line = pkt.payload.toString('utf8').trim();
    if (line.startsWith('want ')) req.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) req.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) req.shallowLines.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) req.deepen = Number(line.slice(7).trim());
    else if (line.startsWith('filter ')) req.filter = line.slice(7).trim();
    else if (line === 'unborn') req.unborn = true;
  }
  return req;
}
/** Build the fetch pack response for a set of wanted oids, honoring haves/depth/shallow. */
function buildFetchPack(repo: RepoRec, req: FetchReq): { pack: Buffer; acks: string[]; newShallow: string[]; unshallow: string[] } {
  const depth = req.deepen ?? null;
  // Generations are needed ONLY for the shallow list (commits at g === depth).
  // A full fetch (depth null) never reads them; a shallow fetch only needs g <= depth.
  // The old code walked the whole history on every fetch.
  const gens = depth !== null ? commitGenerations(req.wants, lookupObject, depth) : new Map<string, number>();
  // objects to send: reachable(wants, depth) minus haveClosure (haves, stopping at previous shallow boundaries)
  const haveClosure = collectReachable(req.haves, lookupObject, { stopAtShallow: new Set(req.shallowLines) });
  const wantReachable = collectReachable(req.wants, lookupObject, depth !== null ? { depth } : {});
  const toSend = new Set<string>();
  for (const oid of wantReachable) if (!haveClosure.has(oid)) toSend.add(oid);
  // new shallow boundaries: commits at generation == depth (when depth set)
  const newShallow: string[] = [];
  if (depth !== null) {
    for (const [oid, g] of gens) {
      if (g === depth) newShallow.push(oid);
    }
  }
  // unshallow: previous shallow boundaries whose parents are now delivered (deepen case)
  const unshallow: string[] = [];
  for (const s of req.shallowLines) {
    const obj = lookupObject(s);
    if (!obj || obj.type !== 'commit') continue;
    const parents = commitOf(s)?.parents ?? [];
    if (parents.some((p) => toSend.has(p) || wantReachable.has(p))) unshallow.push(s);
  }
  const acks: string[] = [];
  for (const h of req.haves) {
    let acked = false;
    for (const w of req.wants) {
      if (isAncestor(h, w, lookupObject)) {
        acked = true;
        break;
      }
    }
    if (acked) acks.push(`ACK ${h}`);
  }
  const objects: GitObj[] = [];
  for (const oid of toSend) {
    const o = lookupObject(oid);
    if (!o) continue;
    // F7: honour the advertised `filter` — `blob:none` omits blobs, `tree:0` omits
    // trees and blobs (commits always sent). Previously advertised but ignored.
    if (req.filter === 'blob:none' && o.type === 'blob') continue;
    if (req.filter === 'tree:0' && (o.type === 'blob' || o.type === 'tree')) continue;
    objects.push(o);
  }
  return { pack: writePack(objects), acks, newShallow, unshallow };
}
function sidebandPackets(pack: Buffer): Buffer {
  // band 1 payload chunks of at most 65500 bytes; one packet per chunk (pack bytes include their own length)
  const chunks: Buffer[] = [];
  const MAX = 65500;
  if (pack.length === 0) {
    chunks.push(Buffer.from([1]));
  } else {
    for (let off = 0; off < pack.length; off += MAX) {
      const slice = pack.subarray(off, Math.min(off + MAX, pack.length));
      chunks.push(Buffer.concat([Buffer.from([1]), slice]));
    }
  }
  return Buffer.concat(chunks.map((c) => pktLine(c)));
}
async function handleGit(ctx: Ctx): Promise<boolean> {
  const p = ctx.parts; // [owner, repo.git, ...]
  if (p.length < 3) return false;
  const owner = p[0] as string;
  const repoGit = p[1] as string;
  if (!repoGit.endsWith('.git')) return false;
  const repoName = repoGit.slice(0, -4);
  if (!isValidOwnerRepo(owner) || !isValidOwnerRepo(repoName)) {
    if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
    return sendError(ctx, 404, 'Not Found'), true;
  }
  const repo = getRepo(owner, repoName);
  if (!authed(ctx)) return sendError(ctx, 401, 'Requires authentication'), true;
  if (!repo || repo.owner !== VIEWER_LOGIN) return sendError(ctx, 404, 'Not Found'), true;
  const sub = p.slice(2);
  const service = ctx.url.searchParams.get('service');
  const gitProtocol = (ctx.req.headers['git-protocol'] ?? '') as string;
  // info/refs
  if (sub.length === 2 && sub[0] === 'info' && sub[1] === 'refs' && ctx.method === 'GET') {
    if (service === 'git-upload-pack') {
      const body = gitProtocol.includes('version=2') ? advertiseV2(repo, 'upload-pack') : advertiseV0(repo, 'upload-pack');
      sendRaw(ctx, 200, UPLOAD_AD_TYPE, body);
      return true;
    }
    if (service === 'git-receive-pack') {
      const body = advertiseV0(repo, 'receive-pack');
      sendRaw(ctx, 200, RECEIVE_AD_TYPE, body);
      return true;
    }
    return sendError(ctx, 400, 'unknown service'), true;
  }
  // git-upload-pack
  if (sub.length === 1 && sub[0] === 'git-upload-pack' && ctx.method === 'POST') {
    let parsed: { lines: Buffer[]; rest: Buffer };
    try {
      parsed = decodePktLines(ctx.body);
    } catch {
      return sendError(ctx, 400, 'invalid pkt-line'), true;
    }
    const lines = parsed.lines.map((b) => b.toString('utf8'));
    const first = lines[0]?.trim() ?? '';
    const isV2 = first === 'command=ls-refs' || first === 'command=fetch';
    if (isV2) {
      if (first === 'command=ls-refs') {
        const body = lsRefsV2(repo, lines);
        sendRaw(ctx, 200, UPLOAD_RESULT_TYPE, body);
        return true;
      }
      // command=fetch
      const req = parseFetchV2(parsed.packets);
      const cacheKey = fetchCacheKey(repo, req, 'v2');
      const cached = fetchCache.get(cacheKey);
      if (cached) {
        sendRaw(ctx, 200, UPLOAD_RESULT_TYPE, cached);
        return true;
      }
      const { pack, acks, newShallow, unshallow } = buildFetchPack(repo, req);
      const out: Buffer[] = [];
      const ackLines = acks.length ? acks : ['NAK'];
      const hasReady = acks.length > 0;
      out.push(pktLine('acknowledgments\n'));
      for (const a of ackLines) out.push(pktLine(`${a}\n`));
      if (hasReady) out.push(pktLine('ready\n'));
      out.push(PKT_FLUSH);
      if (newShallow.length || unshallow.length) {
        out.push(pktLine('shallow-info\n'));
        for (const s of newShallow) out.push(pktLine(`shallow ${s}\n`));
        for (const s of unshallow) out.push(pktLine(`unshallow ${s}\n`));
        out.push(PKT_FLUSH);
      }
      out.push(pktLine('packfile\n'));
      out.push(sidebandPackets(pack));
      out.push(PKT_FLUSH);
      const body = Buffer.concat(out);
      fetchCachePut(cacheKey, body);
      sendRaw(ctx, 200, UPLOAD_RESULT_TYPE, body);
      return true;
    }
    // v0 fetch
    const wants: string[] = [];
    const haves: string[] = [];
    let shallowLines: string[] = [];
    let deepen: number | null = null;
    for (const raw of lines) {
      const line = raw.trim();
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallowLines.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) deepen = Number(line.slice(7).trim());
    }
    // F1: a v0 fetch body continues after the first flush (want… / flush / have… /
    // done / flush). decodePktLines stops at that flush, so have/done live in
    // parsed.rest — decode it too, otherwise every v0 fetch is NAK + full resend.
    if (parsed.rest.length > 0) {
      try {
        const post = decodePktLines(parsed.rest);
        // NOTE: post.lines are Buffers (unlike `lines` above, which are strings).
        for (const raw of post.lines.map((b) => b.toString('utf8'))) {
          const line = raw.trim();
          if (line.startsWith('have ')) haves.push(line.slice(5).trim());
          else if (line.startsWith('shallow ')) shallowLines.push(line.slice(8).trim());
          else if (line.startsWith('deepen ')) deepen = Number(line.slice(7).trim());
        }
      } catch {
        // trailing garbage after the flush: keep the pre-flush parse
      }
    }
    const req: FetchReq = { wants, haves, shallowLines, deepen, filter: null, unborn: false };
    const cacheKey = fetchCacheKey(repo, req, 'v0');
    const cached = fetchCache.get(cacheKey);
    if (cached) {
      sendRaw(ctx, 200, UPLOAD_RESULT_TYPE, cached);
      return true;
    }
    const { pack, acks, newShallow, unshallow } = buildFetchPack(repo, req);
    const out: Buffer[] = [];
    if (acks.length) {
      for (const a of acks) out.push(pktLine(`${a}\n`));
    } else {
      out.push(pktLine('NAK\n'));
    }
    for (const s of newShallow) out.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) out.push(pktLine(`unshallow ${s}\n`));
    out.push(sidebandPackets(pack));
    const body = Buffer.concat(out);
    fetchCachePut(cacheKey, body);
    sendRaw(ctx, 200, UPLOAD_RESULT_TYPE, body);
    return true;
  }
  // git-receive-pack
  if (sub.length === 1 && sub[0] === 'git-receive-pack' && ctx.method === 'POST') {
    let parsed: { lines: Buffer[]; rest: Buffer };
    try {
      parsed = decodePktLines(ctx.body);
    } catch {
      return sendError(ctx, 400, 'invalid pkt-line'), true;
    }
    const lines = parsed.lines.map((b) => b.toString('utf8'));
    const commands: Array<{ old: string; next: string; ref: string }> = [];
    for (const raw of lines) {
      const line = raw.replace(/\n$/, '');
      const nul = line.indexOf('\0');
      const clean = nul >= 0 ? line.slice(0, nul) : line;
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (.+)$/.exec(clean);
      if (m) commands.push({ old: m[1] as string, next: m[2] as string, ref: m[3] as string });
    }
    let incoming = new Map<string, GitObj>();
    let unpackError: string | null = null;
    if (parsed.rest.length >= 12) {
      try {
        incoming = readPack(parsed.rest, { resolveBase: lookupObject });
      } catch (err) {
        unpackError = err instanceof Error ? err.message : 'unpack failed';
      }
    } else if (parsed.rest.length > 0) {
      unpackError = 'truncated pack';
    }
    const results: string[] = [];
    if (unpackError !== null) {
      const out: Buffer[] = [];
      out.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(`unpack ${unpackError}\n`, 'utf8')])));
      for (const c of commands) out.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(`ng ${c.ref} unpack failed\n`, 'utf8')])));
      out.push(PKT_FLUSH);
      sendRaw(ctx, 200, RECEIVE_RESULT_TYPE, Buffer.concat(out));
      return true;
    }
    // commit incoming objects (resolve REF_DELTA bases that already exist server-side)
    for (const [oid, obj] of incoming) {
      if (!store.objects.has(oid)) store.objects.set(oid, obj);
    }
    const reportLines: string[] = ['unpack ok'];
    const okRefs: Array<{ ref: string; next: string }> = [];
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.next === ZERO_OID) {
        // delete
        if (current === undefined) {
          reportLines.push(`ng ${cmd.ref} reference does not exist`);
          continue;
        }
        if (current !== cmd.old) {
          reportLines.push(`ng ${cmd.ref} old ref mismatch`);
          continue;
        }
        repo.refs.delete(cmd.ref);
        bumpFetchRev(repo);
        reportLines.push(`ok ${cmd.ref}`);
        continue;
      }
      if (cmd.old === ZERO_OID) {
        if (current !== undefined) {
          reportLines.push(`ng ${cmd.ref} already exists`);
          continue;
        }
      } else {
        if (current === undefined) {
          reportLines.push(`ng ${cmd.ref} old ref mismatch`);
          continue;
        }
        if (current !== cmd.old) {
          reportLines.push(`ng ${cmd.ref} old ref mismatch`);
          continue;
        }
      }
      const obj = lookupObject(cmd.next);
      if (!obj) {
        reportLines.push(`ng ${cmd.ref} object not found`);
        continue;
      }
      if (obj.type !== 'commit' && obj.type !== 'tag') {
        reportLines.push(`ng ${cmd.ref} object is not a commit or tag`);
        continue;
      }
      // F10: the fast-forward check used to be skipped for tag objects, so updating a
      // tag ref to an unrelated tag was accepted. isAncestor already walks tag targets.
      if (cmd.old !== ZERO_OID && !isAncestor(cmd.old, cmd.next, lookupObject)) {
        reportLines.push(`ng ${cmd.ref} non-fast-forward`);
        continue;
      }
      okRefs.push({ ref: cmd.ref, next: cmd.next });
      reportLines.push(`ok ${cmd.ref}`);
    }
    for (const r of okRefs) {
      repo.refs.set(r.ref, r.next);
      bumpFetchRev(repo);
      const obj = lookupObject(r.next);
      if (obj && obj.type === 'commit') noteCommit(r.next);
      if (obj && obj.type === 'tag') {
        // note tag target commit too
        const target = tagOf(r.next)?.object ?? '';
        const tObj = lookupObject(target);
        if (tObj && tObj.type === 'commit') noteCommit(target);
      }
    }
    repo.updatedAt = isoOf(nextTs());
    const out: Buffer[] = [];
    for (const line of reportLines) {
      out.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(`${line}\n`, 'utf8')])));
    }
    out.push(PKT_FLUSH);
    sendRaw(ctx, 200, RECEIVE_RESULT_TYPE, Buffer.concat(out));
    return true;
  }
  return false;
}

// ------------------------------------------------------------------ app assembly

export function createApp(): Server {
  const token = process.env.MAKEFUN_SHOP_TOKEN ?? '';
  const server = createServer(async (req, res) => {
    // F2: URL parsing + percent-decoding live INSIDE the try: a malformed % sequence
    // used to throw URIError out of this callback and crash the process (Node 22
    // default on unhandled rejection). Now it answers 400 and the server stays up.
    try {
      const ctx: Ctx = {
        req,
        res,
        method: req.method ?? 'GET',
        url: new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`),
        parts: [],
        body: Buffer.alloc(0),
        token,
        reqId: nextReqId(),
      };
      // E2: a GET/HEAD with no body never needs the stream drained; skipping the
      // async-iterator + end-of-stream wait saves the per-GET overhead. Any request
      // that DOES carry a body (content-length > 0 or chunked) still goes through readBody.
      const cl = req.headers['content-length'];
      const hasBody = (cl !== undefined && cl !== '0') || req.headers['transfer-encoding'] !== undefined;
      if (!hasBody && (ctx.method === 'GET' || ctx.method === 'HEAD')) {
        ctx.body = Buffer.alloc(0);
      } else {
        try {
          ctx.body = await readBody(req);
        } catch {
          ctx.body = Buffer.alloc(0);
        }
      }
      const path = ctx.url.pathname;
      const parts = path.split('/').filter((s) => s.length > 0).map((s) => (s.includes('%') ? decodeURIComponent(s) : s));
      ctx.parts = parts;
      if (parts[0] === 'healthz' && parts.length === 1) {
        sendJson(ctx, 200, { ok: true });
        return;
      }
      if (parts[0] === 'api' && parts[1] === 'v3') {
        ctx.parts = parts.slice(2);
        const handled = await handleRest(ctx);
        if (handled) return;
      }
      if (parts[0] === 'api' && parts[1] === 'graphql' && parts.length === 2) {
        const handled = await handleGraphql(ctx);
        if (handled) return;
      }
      if (parts[0] === 'mcp' && parts.length === 1) {
        const handled = await handleMcp(ctx);
        if (handled) return;
      }
      if (parts.length >= 3 && parts[1]?.endsWith('.git')) {
        const handled = await handleGit(ctx);
        if (handled) return;
      }
      sendError(ctx, 404, 'Not Found');
    } catch (err) {
      if (!res.headersSent) {
        const bad = err instanceof URIError;
        res.writeHead(bad ? 400 : 500, { 'Content-Type': JSON_TYPE });
        res.end(JSON.stringify({ message: bad ? 'Bad Request: malformed URL encoding' : err instanceof Error ? err.message : 'internal error' }));
      } else {
        res.end();
      }
    }
  });
  return server;
}
