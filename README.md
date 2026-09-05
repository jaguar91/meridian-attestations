# meridian-attestations

The public hash-commitment log for MERIDIAN signals. One manifest per UTC
day, every day — including days with zero signals — each committing to the
receipts that fired that day, chained to the previous manifest, and anchored
to external clocks the moment it is published.

**This repo contains hashes and manifests only.** No receipt content, no
payloads, nothing revocable. Signal receipts are revealed later, on the
published schedule; when they are, this log is what makes the reveal
checkable.

## What this log lets you prove — without trusting us

You are the intended audience of this README if you do not trust us. Good.
Clone the repo and run the verifier (any Node.js ≥ 20, no packages):

```
node verify/verify.mjs
```

A clean exit proves, from your own copy, that:

- **nothing published here was ever edited, reordered, inserted, or
  deleted.** Every manifest's bytes hash into its successor
  (`prev_manifest_sha256`), sequence numbers and calendar days are gapless,
  and a manifest for every day must exist — so a missing day is evidence of
  tampering, never ambiguity.
- **every manifest is anchored in time.** Each has an OpenTimestamps proof
  (`proofs/<year>/<date>.json.ots`) committing to its exact bytes. The
  verifier checks the binding structurally; for the Bitcoin-level check, use
  the [reference client](https://github.com/opentimestamps/opentimestamps-client):

  ```
  ots verify proofs/2026/2026-09-20.json.ots -f manifests/2026/2026-09-20.json
  ```

  Most manifests also carry an RFC 3161 token (`.tsr`) from a public
  timestamping authority as an instant second anchor:

  ```
  openssl ts -reply -in proofs/2026/2026-09-20.json.tsr -text
  ```
- **a reveal cannot cherry-pick.** Every manifest publishes its receipt
  *count* and the ordered hash list. Given revealed receipts
  (`node verify/verify.mjs --receipts receipts.json`), the verifier requires
  them to match count-for-count, hash-for-hash, in publish order. Fire 40,
  reveal 25 winners — the log says 40, and the reveal fails.

## What it deliberately does not prove

Stated here so nobody upgrades the claim:

- It does **not** prove a signal was *good* — only that it was published when
  claimed, unchanged, and completely revealed.
- OpenTimestamps proves **no later than** its Bitcoin attestation; the
  strictly-daily chained cadence is what bounds *no earlier than* (a receipt
  hash cannot appear in a manifest whose successors are already anchored).
- Unrevealed hashes prove nothing about their content until revealed. That is
  intentional — receipts include a mandatory 32-byte random nonce precisely
  so their hashes resist dictionary attack until reveal.

## How to read a manifest

```
manifests/2026/2026-09-20.json      ← the manifest (its BYTES are canonical:
proofs/2026/2026-09-20.json.ots     ← OpenTimestamps proof of those bytes
proofs/2026/2026-09-20.json.tsr     ← RFC 3161 token for the same digest
```

Manifest files are stored as their exact RFC 8785 (JCS) canonical
serialization, so `sha256(file bytes)` **is** the manifest's hash — the same
value in the next manifest's `prev_manifest_sha256`, in the OTS proof, and in
the RFC 3161 message imprint. `era` labels pre-launch soak (`PRE_SIGNAL`,
always zero receipts), `SHADOW`, and `LIVE`, so the pre-launch log cannot be
misread as a hidden live record. The `governance` block anchors the sha256 of
the project's public decision log at each day's HEAD.

## Operational rules this repo is bound by

- **Never delete, never amend.** A wrong manifest is corrected by a *later*
  manifest referencing it. CI fails any push that modifies, renames, or
  deletes a published manifest; the verifier treats any mutation as
  tampering — including ours.
- The only in-place change ever made under `proofs/` is upgrading a pending
  `.ots` to its Bitcoin-attested form; the upgraded proof must still bind to
  the same manifest bytes, which CI re-checks.
- CI runs the verifier daily and on every push — the log proves itself in
  public, on infrastructure we do not control after the fact.
- Branch protection is a courtesy. The chain, your clones, and the anchors
  are the security. **If you care about this log, clone it** — a clone plus
  yesterday's proof is everything needed to catch a rewrite.
