#!/usr/bin/env node
/**
 * Open verifier for the MERIDIAN attestations log.
 *
 *   node verify/verify.mjs                     # verify the whole chain
 *   node verify/verify.mjs --root <repo>       # ...of a checkout elsewhere
 *   node verify/verify.mjs --receipts r.json   # ...and validate revealed receipts
 *
 * Dependency-free on purpose: node:crypto, node:fs, node:path, nothing else.
 * You should not have to trust our packages to distrust our claims.
 *
 * SOURCE OF TRUTH NOTE. The canonicalization and chain rules below are a
 * deliberate COPY of `src/commitments/canonical.ts` and
 * `src/commitments/manifest.ts` in the private source repo, which remain
 * the source of truth. This file imports nothing from there so that anyone
 * can run it from a bare clone of this public repo; the private repo carries
 * a test (test/commitmentVerifierParity.test.ts) that runs THIS file against
 * chains and receipt sets produced by the private writer, so the two
 * implementations cannot drift apart silently — writer/verifier drift is the
 * §6 failure mode this arrangement exists to prevent.
 *
 * What a clean exit proves, and what it does not (design §8):
 *  - every manifest's bytes are exactly the canonical serialization of its
 *    content, its hash chains from its predecessor, sequences and calendar
 *    days are gapless, and eras never regress — so no published manifest was
 *    edited, reordered, inserted, or deleted;
 *  - every manifest has an OpenTimestamps proof committing to its exact
 *    bytes. This script checks the proof structurally (magic, version,
 *    digest binding). For the Bitcoin-level check, use the reference client:
 *      ots verify proofs/<y>/<date>.json.ots -f manifests/<y>/<date>.json
 *    RFC 3161 tokens (.tsr), where present, can be inspected with:
 *      openssl ts -reply -in proofs/<y>/<date>.json.tsr -text
 *  - revealed receipts, when supplied, match their manifest count-for-count,
 *    hash-for-hash, in publish order — the cherry-pick defense;
 *  - it does NOT prove any signal was good, and unrevealed hashes prove
 *    nothing about their content until revealed. That is by design.
 *
 * Receipts file format for --receipts: a JSON object mapping collection
 * dates to ordered arrays of receipt objects, e.g.
 *   { "2026-09-20": [ { ...receipt fields incl. commitment_nonce... } ] }
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const MANIFEST_SCHEMA_VERSION = '1.0';
export const ERAS = ['PRE_SIGNAL', 'SHADOW', 'LIVE'];

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

// --- canonicalization (copy of src/commitments/canonical.ts, jcs-int-v1) ---
// RFC 8785 (JCS) restricted to the subset the writer permits: integers within
// Number.MAX_SAFE_INTEGER, strings, booleans, null, arrays, plain objects.
// Everything else is refused — a value this rejects could never have been
// committed by the writer, so rejection IS the verdict, not a limitation.

export function canonicalize(value, path = '$') {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error(`${path}: non-finite number`);
    if (!Number.isInteger(value)) throw new Error(`${path}: non-integer number ${value}`);
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) throw new Error(`${path}: integer beyond MAX_SAFE_INTEGER`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v, i) => canonicalize(v, `${path}[${i}]`)).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      if (value[k] === undefined) throw new Error(`${path}.${k}: undefined is not committable`);
      parts.push(`${JSON.stringify(k)}:${canonicalize(value[k], `${path}.${k}`)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`${path}: ${t} is not committable`);
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function commitmentHash(value) {
  return `sha256:${sha256Hex(Buffer.from(canonicalize(value), 'utf8'))}`;
}

// --- manifest shape + chain rules (copy of src/commitments/manifest.ts) ---

export function checkManifestShape(m) {
  const p = [];
  if (typeof m !== 'object' || m === null || Array.isArray(m)) return ['manifest is not a JSON object'];
  if (!Array.isArray(m.receipt_hashes)) return ['receipt_hashes is not an array'];
  if (m.manifest_schema_version !== MANIFEST_SCHEMA_VERSION) p.push(`unknown schema version ${m.manifest_schema_version}`);
  if (!Number.isInteger(m.sequence) || m.sequence < 1) p.push(`sequence ${m.sequence} is not a positive integer`);
  if (!DATE_RE.test(String(m.collection_date))) p.push(`collection_date ${m.collection_date} is not YYYY-MM-DD`);
  if (m.receipt_count !== m.receipt_hashes.length) {
    p.push(`receipt_count ${m.receipt_count} != receipt_hashes.length ${m.receipt_hashes.length}`);
  }
  for (const h of m.receipt_hashes) if (!HASH_RE.test(h)) p.push(`malformed receipt hash ${h}`);
  if (m.prev_manifest_sha256 !== null && !HASH_RE.test(m.prev_manifest_sha256)) {
    p.push(`malformed prev_manifest_sha256 ${m.prev_manifest_sha256}`);
  }
  if (m.sequence === 1 && m.prev_manifest_sha256 !== null) p.push('sequence 1 must have prev_manifest_sha256 null');
  if (m.sequence > 1 && m.prev_manifest_sha256 === null) p.push(`sequence ${m.sequence} is missing its prev link`);
  if (!ERAS.includes(m.era)) p.push(`unknown era ${String(m.era)}`);
  if (!HASH_RE.test(m.governance?.decisions_md_sha256 ?? '')) p.push('malformed governance.decisions_md_sha256');
  if (!Number.isInteger(m.governance?.governance_records_count) || m.governance.governance_records_count < 0) {
    p.push('governance_records_count is not a non-negative integer');
  }
  if (m.era === 'PRE_SIGNAL' && m.receipt_count !== 0) p.push('PRE_SIGNAL manifests must carry zero receipts');
  return p;
}

export function nextUtcDay(date) {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

// --- OpenTimestamps structural check ---------------------------------------
// \x00OpenTimestamps\x00\x00Proof\x00 + 8 magic bytes, version 1, sha256
// file-hash op (0x08), then the 32-byte digest the proof commits to.

const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');

export function checkOtsProof(bytes, expectedDigestHex) {
  const p = [];
  if (bytes.length < OTS_MAGIC.length + 35) return [`proof too short (${bytes.length} bytes)`];
  if (!bytes.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC)) return ['not an OTS detached proof (bad magic)'];
  let pos = OTS_MAGIC.length;
  // varint version
  let version = 0;
  let shift = 0;
  for (;;) {
    const b = bytes[pos++];
    version += (b & 0x7f) * 2 ** shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
    if (shift > 42 || pos >= bytes.length) return ['malformed version varint'];
  }
  if (version !== 1) p.push(`unsupported OTS version ${version}`);
  if (bytes[pos] !== 0x08) p.push(`file-hash op is 0x${bytes[pos].toString(16)}, expected sha256 (0x08)`);
  pos += 1;
  const digest = bytes.subarray(pos, pos + 32).toString('hex');
  if (digest !== expectedDigestHex) {
    p.push(`proof commits to digest ${digest.slice(0, 16)}…, manifest file is ${expectedDigestHex.slice(0, 16)}…`);
  }
  if (bytes.length <= pos + 32) p.push('no timestamp tree after the digest');
  return p;
}

// --- RFC 3161 structural check ---------------------------------------------
// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, token OPTIONAL }.
// status 0/1 = granted; a granted response must actually carry the token.

export function checkTsrToken(bytes) {
  try {
    const tl = (pos) => {
      const tag = bytes[pos];
      let length = bytes[pos + 1];
      let headerLen = 2;
      if (length > 0x80) {
        const n = length & 0x7f;
        if (n > 4) throw new Error('bad long-form DER length');
        length = 0;
        for (let i = 0; i < n; i++) length = length * 256 + bytes[pos + 2 + i];
        headerLen = 2 + n;
      } else if (length === 0x80) throw new Error('indefinite length is not DER');
      if (pos + headerLen + length > bytes.length) throw new Error('DER value runs past end');
      return { tag, length, headerLen };
    };
    const outer = tl(0);
    if (outer.tag !== 0x30) return ['not a TimeStampResp (outer tag is not SEQUENCE)'];
    const info = tl(outer.headerLen);
    if (info.tag !== 0x30) return ['PKIStatusInfo is not a SEQUENCE'];
    const st = tl(outer.headerLen + info.headerLen);
    if (st.tag !== 0x02) return ['PKIStatus is not an INTEGER'];
    let status = 0;
    for (let i = 0; i < st.length; i++) status = status * 256 + bytes[outer.headerLen + info.headerLen + st.headerLen + i];
    if (status > 1) return [`TSA status ${status} — not granted`];
    const infoEnd = outer.headerLen + info.headerLen + info.length;
    if (infoEnd >= outer.headerLen + outer.length) return ['granted but no timestamp token attached'];
    return [];
  } catch (err) {
    return [`malformed DER: ${err.message}`];
  }
}

// --- the walk ---------------------------------------------------------------

export function verifyRepo(root, receiptsByDate = {}) {
  const problems = [];
  const notes = [];
  const manifestsDir = join(root, 'manifests');
  if (!existsSync(manifestsDir)) {
    return { problems: [`no manifests/ directory under ${root}`], notes, manifests: 0, receiptsChecked: 0 };
  }

  const files = [];
  for (const year of readdirSync(manifestsDir).sort()) {
    for (const f of readdirSync(join(manifestsDir, year)).sort()) {
      if (f.endsWith('.json')) files.push({ year, name: f, path: join(manifestsDir, year, f) });
    }
  }
  if (files.length === 0) problems.push('manifests/ holds no manifests');

  let prev = null;
  let prevFileHash = null;
  let tsrMissing = 0;
  const byDate = new Map();
  for (const file of files) {
    const rel = `manifests/${file.year}/${file.name}`;
    const bytes = readFileSync(file.path);
    let m;
    try {
      m = JSON.parse(bytes.toString('utf8'));
    } catch {
      problems.push(`${rel}: not parseable JSON`);
      continue;
    }
    byDate.set(m.collection_date, m);
    // Byte-canonical: a reformatted file parses identically while every hash
    // and anchor breaks — treat the bytes, not the parse, as the manifest.
    try {
      if (canonicalize(m) !== bytes.toString('utf8')) {
        problems.push(`${rel}: bytes are not the canonical serialization of their content — the file was rewritten`);
      }
    } catch (err) {
      problems.push(`${rel}: not canonicalizable (${err.message})`);
    }
    for (const s of checkManifestShape(m)) problems.push(`${rel}: ${s}`);
    if (typeof m !== 'object' || m === null || Array.isArray(m) || typeof m.collection_date !== 'string') {
      continue; // too malformed to chain — already reported above
    }
    if (file.name !== `${m.collection_date}.json` || file.year !== m.collection_date.slice(0, 4)) {
      problems.push(`${rel}: path does not match collection_date ${m.collection_date}`);
    }

    if (prev === null) {
      if (m.sequence !== 1) problems.push(`${rel}: chain starts at sequence ${m.sequence}, not 1 — earlier manifests are missing`);
    } else {
      if (m.sequence !== prev.sequence + 1) problems.push(`${rel}: sequence gap after ${prev.sequence}`);
      if (m.collection_date !== nextUtcDay(prev.collection_date)) {
        problems.push(`${rel}: calendar gap after ${prev.collection_date} — a missing day is evidence, not ambiguity`);
      }
      if (m.prev_manifest_sha256 !== `sha256:${prevFileHash}`) {
        problems.push(`${rel}: prev_manifest_sha256 does not match the previous manifest's actual bytes — a prior manifest changed`);
      }
      if (ERAS.indexOf(m.era) < ERAS.indexOf(prev.era)) {
        problems.push(`${rel}: era regressed ${prev.era} -> ${m.era}`);
      }
    }

    const fileHash = sha256Hex(bytes);
    const otsPath = join(root, 'proofs', file.year, `${file.name}.ots`);
    if (!existsSync(otsPath)) {
      problems.push(`${rel}: no OTS proof at proofs/${file.year}/${file.name}.ots — pending stamps are committed immediately by design`);
    } else {
      for (const s of checkOtsProof(readFileSync(otsPath), fileHash)) {
        problems.push(`proofs/${file.year}/${file.name}.ots: ${s}`);
      }
    }
    const tsrPath = join(root, 'proofs', file.year, `${file.name}.tsr`);
    if (existsSync(tsrPath)) {
      for (const s of checkTsrToken(readFileSync(tsrPath))) problems.push(`proofs/${file.year}/${file.name}.tsr: ${s}`);
    } else {
      tsrMissing += 1; // best-effort second anchor — worth a note, never a failure
    }

    prev = m;
    prevFileHash = fileHash;
  }
  if (tsrMissing > 0) notes.push(`${tsrMissing} manifest(s) have no RFC 3161 token (optional second anchor; OTS is the clock)`);

  // --- revealed receipts: count-for-count, hash-for-hash, in order ---------
  let receiptsChecked = 0;
  for (const [date, receipts] of Object.entries(receiptsByDate)) {
    const m = byDate.get(date);
    if (!m) {
      problems.push(`receipts for ${date}: no manifest exists for that date`);
      continue;
    }
    if (!Array.isArray(receipts)) {
      problems.push(`receipts for ${date}: expected an ordered array`);
      continue;
    }
    if (receipts.length !== m.receipt_count) {
      problems.push(
        `receipts for ${date}: reveal has ${receipts.length} receipts against a committed count of ${m.receipt_count} — completeness fails`,
      );
    }
    const n = Math.min(receipts.length, m.receipt_hashes.length);
    for (let i = 0; i < n; i++) {
      let got;
      try {
        got = commitmentHash(receipts[i]);
      } catch (err) {
        problems.push(`receipts for ${date}[${i}]: not canonicalizable (${err.message}) — the writer could never have committed this`);
        continue;
      }
      if (got !== m.receipt_hashes[i]) {
        problems.push(`receipts for ${date}[${i}]: hash ${got.slice(0, 23)}… != committed ${m.receipt_hashes[i].slice(0, 23)}…`);
      }
      receiptsChecked += 1;
    }
  }

  return { problems, notes, manifests: files.length, receiptsChecked, first: files[0]?.name, last: files.at(-1)?.name };
}

// --- CLI --------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  let root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  let receiptsFile = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--root') root = resolve(args[++i]);
    else if (args[i] === '--receipts') receiptsFile = resolve(args[++i]);
    else if (args[i] === '--help' || args[i] === '-h') {
      console.log('usage: node verify/verify.mjs [--root <repo>] [--receipts <file.json>]');
      process.exit(0);
    } else {
      console.error(`unknown argument: ${args[i]}`);
      process.exit(2);
    }
  }

  let receipts = {};
  if (receiptsFile !== null) {
    try {
      receipts = JSON.parse(readFileSync(receiptsFile, 'utf8'));
    } catch (err) {
      console.error(`cannot read receipts file ${receiptsFile}: ${err.message}`);
      process.exit(2);
    }
  }

  const r = verifyRepo(root, receipts);
  for (const n of r.notes) console.log(`note: ${n}`);
  if (r.problems.length > 0) {
    for (const p of r.problems) console.error(`FAIL: ${p}`);
    console.error(`\nVERIFICATION FAILED — ${r.problems.length} problem(s) across ${r.manifests} manifest(s).`);
    process.exit(1);
  }
  console.log(
    `OK — ${r.manifests} manifest(s) verified (${r.first ?? '-'} … ${r.last ?? '-'}), chain intact, ` +
      `every manifest anchored; ${r.receiptsChecked} revealed receipt(s) checked.`,
  );
  console.log('Bitcoin-level anchor check: ots verify proofs/<y>/<date>.json.ots -f manifests/<y>/<date>.json');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
