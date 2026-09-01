# RFC: Vendor evidence export profile

**Status:** Proposed. This is a design sketch, not implemented. It depends on
the buy-side milestone (renewal gates, the vendor registry evidence references,
the gateway, and behavioral fingerprints) and should not be built until those
vendor-independent sources have shipped and have real usage.

## Problem

The buy-side milestone governs licensed and embedded AI without asking the
vendor for anything. Sign-in logs, gateway telemetry, expiring references,
scheduled black-box evals, and release-note feeds all work against a vendor who
stays silent. That independence is deliberate and it is the reason the milestone
works: a mechanism that needs vendor cooperation is a questionnaire, and a
questionnaire is the thing this product exists to replace.

But some evidence a buyer wants cannot be observed from the outside, or can only
be guessed at high cost:

- Which exact model version is behind an endpoint right now. Behavioral
  fingerprints (the black-box eval source) infer that a change happened; they
  cannot name what changed or when.
- The current subprocessor list, so a buyer knows when a fourth party enters the
  chain before it shows up in an incident.
- A material change or incident the moment the vendor knows, rather than when a
  release-note feed happens to publish it.

Today a buyer gets these facts, if at all, from a questionnaire answer that is
stale the moment it is saved. The question this RFC answers: is there a way for a
cooperating vendor to publish these facts continuously, in a form the buyer can
verify and rank honestly against everything else, without the buyer ever
having to trust the vendor's word?

## Goal

Define a **read-only, signed evidence export** that a vendor's own Norinth
instance can expose and a buyer's Norinth can ingest as one more buy-side
evidence source. The design has three fixed properties:

1. **It is an export surface, not a new SDK.** A vendor who already runs Norinth
   on the build side (its own model inventory, evals, incidents) exposes a
   scoped, per-customer view of evidence it already holds. There is nothing new
   for the vendor to instrument. Vendors who do not run Norinth publish a static
   signed document in the same schema; the profile is the interchange format, not
   a runtime dependency.
2. **It is never load-bearing.** No renewal gate, finding, or review may require
   a vendor export to exist. Every gate must reach its decision from the
   vendor-independent sources alone. The export can only add evidence or raise a
   review; it can never be the thing that unblocks a renewal on its own.
3. **It is ranked as a claim, and a claim never outranks an observation.** A
   signed vendor attestation sits above a questionnaire answer and below anything
   the buyer observed directly (gateway telemetry, black-box eval results,
   sign-in logs). When a vendor export and an observation disagree, the
   observation wins and the disagreement itself opens a review. This is the same
   rule the product already applies when a form and telemetry disagree.

## Non-goals

- A vendor-facing trust-center product. Publishing continuous evidence to buyers
  is a real sell-side need, but it is a different product with a different buyer
  and sales motion. This RFC covers only the interchange format and the buyer's
  ingestion of it.
- Any change to the trust ranking that lets vendor-authored evidence satisfy a
  gate a buyer could not otherwise satisfy.
- Content-bearing evidence. As with vendor evidence references, the export
  carries names, identifiers, versions, dates, and hashes, never document bodies
  and never questionnaire text.
- A new signing primitive. The export reuses the existing Ed25519 attestation
  keys (`storage/attestation_keys.py`), the same mechanism that binds signed
  `eval.result` evidence to a CI identity today.

## Design

### 1. The export is a set of signed, typed attestations

An export item reuses the platform's versioned event envelope
(`schema_version`) and adds a small set of buy-side attestation types. Each item
is a name, identifiers, versions, dates, and hashes, signed with the vendor's
Ed25519 key. Proposed types:

- `vendor.model_provenance`: for a named endpoint or product, the current model
  family, version, and a content hash of the served configuration, with an
  effective-from date.
- `vendor.subprocessor_set`: the current list of subprocessors by name and role,
  with an effective-from date.
- `vendor.material_change`: a declared model update, incident, or subprocessor
  change, with a class, a summary hash, and a timestamp.
- `vendor.reference_assertion`: a machine-readable restatement of a compliance
  reference (BAA, DPA, SOC 2, ISO 42001, FDA clearance) as identifier, issue
  date, expiry date, and document hash. This mirrors the vendor evidence
  references the buyer already stores by hand, so it can populate them, not
  replace the buyer's own record of them.

### 2. The buyer registers the vendor's public key on the registry entry

The `vendor_registry` entry gains an optional attestation public key and a feed
location (a pull URL the buyer polls, or an inbound signed document the buyer
uploads). Registration is an audited governance mutation, same as any registry
change. Only the public key is stored. A registry entry with no key ingests no
exports; the feature is off until a buyer deliberately turns it on for a named
vendor.

### 3. Ingestion verifies the signature and ranks the item as a claim

An export item is accepted only if its signature verifies against the key pinned
on the registry entry, exactly as signed `eval.result` items are verified at
ingestion today. A verified item becomes evidence scoped to the dependent
systems, tagged with an evidence rank of `vendor_attested`, which the trust
ranking places above `self_reported` (questionnaire) and below `observed`
(gateway, black-box eval, sign-in). An item that fails verification is dropped
to the delivery log, never silently accepted.

### 4. The export can raise reviews but not clear them

A `vendor.material_change` opens exactly one material-change review on each
dependent system, the same review path the release-note feed and the black-box
eval source open, and pairs with them: the announced change arrives here, the
silent change is still caught by the black-box source, and a change announced
here that the black-box source does not corroborate is itself worth a look. A
`vendor.reference_assertion` whose expiry precedes the buyer's recorded expiry
shortens coverage; one that claims a longer expiry than the buyer can verify does
not extend it, it opens a review. Nothing in the export can close a finding or
approve a renewal.

### 5. Provenance disagreement is a first-class signal

When `vendor.model_provenance` says the served model is unchanged but the
black-box eval source has flagged drift, that contradiction is the highest-value
output of the whole feature: the vendor's own record disagrees with observed
behavior. It opens a review carrying both the attestation and the eval score
sets. This is the case that a questionnaire can never produce, because a
questionnaire has no timestamp a machine can compare against an observation.

## Trust ranking

The product already ranks a form below telemetry. This RFC inserts one rank
between them and makes the order explicit:

1. `observed`: gateway telemetry, black-box eval results, identity-provider
   sign-ins. The buyer produced this itself.
2. `vendor_attested`: a signed export item verified against a pinned key. The
   buyer did not produce it, but it cannot be forged and it carries a timestamp.
3. `self_reported`: a questionnaire answer or an unsigned document reference the
   buyer typed in.

A gate reads from rank 1. Ranks 2 and 3 enrich the record and can open reviews.
When two ranks disagree, the higher rank wins and the disagreement opens a
review. No configuration can reorder these.

## Migration / rollout (phased, each phase shippable)

1. **Interchange schema only.** Publish the attestation types and the signing
   profile as a versioned spec under `schema_version`, with a validator and no
   ingestion path. This lets the format exist and be reviewed before anything
   consumes it.
2. **Buyer ingestion, pull.** Add the registry public key and feed URL, the
   poll, signature verification, and the `vendor_attested` rank. Wire
   `vendor.material_change` into the existing review path and
   `vendor.reference_assertion` into the existing references. No vendor-side code
   ships in this phase; a buyer can test it against a static signed document.
3. **Vendor export view.** On the build-side instance, add the scoped,
   per-customer read-only export of provenance, subprocessors, and material
   changes the vendor already holds, signed with its attestation key. This is the
   only phase that touches the vendor side, and it is the last one.
4. **Open the spec.** Once both sides speak the schema in practice, publish the
   attestation profile as an open specification so a vendor can implement the
   export without running Norinth. The moat is being on both sides of enough
   relationships to define the format, not the connector.

## Decisions (made)

- **Export items are ranked below observations, permanently.** A vendor's signed
  word is stronger than a questionnaire and weaker than what the buyer saw. This
  is not configurable, because the audit story depends on a gate meaning the same
  thing regardless of vendor cooperation.
- **The export never gates.** A buyer who turns off every vendor export must
  still reach every renewal decision. Vendor cooperation is enrichment, never a
  dependency.
- **Reuse the attestation-key primitive.** No new signing scheme. A vendor key is
  registered and verified the same way a CI eval-signing key is today.
- **Names, dates, and hashes only.** No document bodies, consistent with vendor
  evidence references.

## Open questions

- Feed transport: buyer-pull polling versus vendor-push upload. Pull keeps the
  buyer in control of when and whether it connects; push gets material changes to
  the buyer faster. Phase 2 starts with pull; push is a later option.
- Key rotation and revocation for vendor keys, and how a buyer is notified when a
  vendor rotates. The attestation-key store already models rotation for CI keys;
  the vendor case likely reuses it.
- Whether `vendor.reference_assertion` should require a resolvable, independently
  checkable identifier (for example an auditor registry entry) before it can
  populate a reference, rather than the vendor's own assertion of it.

## Notes on effort

Phases 1 and 2 are small because the machinery exists: the event envelope, the
Ed25519 verification path, the vendor registry, the references, the review path,
and the delivery log are all already in the tree. The real cost is phase 3 on the
build-side instance and the ongoing work of keeping the interchange spec stable
enough that a third party can implement it. None of it should start until the
vendor-independent buy-side sources have shipped and shown that buyers act on
them, because the value of a cooperating-vendor feature is bounded by how much a
buyer already trusts the record it enriches.
