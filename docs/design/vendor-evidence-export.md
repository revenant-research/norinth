# RFC: Vendor evidence export profile

**Status:** Proposed. Not implemented. Depends on the buy-side milestone (renewal gates, vendor evidence references, the gateway, behavioral fingerprints). Build it last, after those sources ship and are in use.

## Problem

The buy-side sources govern licensed AI without asking the vendor for anything. That is on purpose: anything that needs vendor cooperation is a questionnaire, and the whole point is to replace questionnaires.

But some facts cannot be seen from outside, or cost too much to guess:

- Which model version is behind an endpoint right now. Behavioral fingerprints detect that a change happened; they cannot say what changed or when.
- The current subprocessor list, so a buyer knows a fourth party entered the chain before it shows up in an incident.
- A material change or incident when the vendor first knows it, not when a release-note feed happens to publish it.

Today a buyer gets these from a questionnaire answer that is stale the moment it is saved. This RFC lets a cooperating vendor publish them as signed evidence the buyer verifies and ranks, with no need to trust the vendor's word.

## Goal

A read-only, signed evidence export that a vendor's own instance exposes and a buyer's instance ingests as one more buy-side source. Three fixed rules:

1. **Export surface, not a new SDK.** A vendor already running the platform exposes evidence it already holds, scoped per customer. Nothing new to instrument. Vendors who do not run the platform publish a static signed document in the same schema.
2. **Never load-bearing.** No gate, finding, or renewal may require an export. Every gate decides from the vendor-independent sources alone. An export can add evidence or open a review; it cannot unblock a renewal.
3. **Ranked below observations.** A signed vendor attestation ranks above a questionnaire answer and below anything the buyer observed directly (gateway telemetry, black-box evals, sign-in logs). When an export and an observation disagree, the observation wins and the gap opens a review. This is the rule the product already applies when a form and telemetry disagree.

## Non-goals

- A vendor-facing trust-center product. Publishing evidence to buyers is a sell-side need with a different buyer and sales motion. This RFC covers only the format and the buyer's ingestion of it.
- Any ranking change that lets vendor-authored evidence satisfy a gate the buyer could not otherwise satisfy.
- Document bodies. The export carries names, identifiers, versions, dates, and hashes, never document content and never questionnaire text.
- A new signing scheme. It reuses the Ed25519 attestation keys in `storage/attestation_keys.py`, the same mechanism that binds signed `eval.result` evidence to a CI identity today.

## Design

### 1. The export is a set of signed, typed attestations

Each item reuses the versioned event envelope (`schema_version`) and adds a small set of buy-side types. An item is a name, identifiers, versions, dates, and hashes, signed with the vendor's Ed25519 key:

- `vendor.model_provenance`: for a named endpoint or product, the current model family, version, and a content hash of the served config, with an effective-from date.
- `vendor.subprocessor_set`: the current subprocessor list by name and role, with an effective-from date.
- `vendor.material_change`: a declared model update, incident, or subprocessor change, with a class, a summary hash, and a timestamp.
- `vendor.reference_assertion`: a compliance reference (BAA, DPA, SOC 2, ISO 42001, FDA clearance) as identifier, issue date, expiry date, and document hash. It populates the buyer's own vendor evidence references; it does not replace them.

### 2. The buyer registers the vendor's public key on the registry entry

The `vendor_registry` entry gains an optional attestation public key and a feed location (a pull URL the buyer polls, or an inbound signed document the buyer uploads). Registration is an audited governance mutation. Only the public key is stored. An entry with no key ingests nothing; the feature is off until a buyer turns it on for a named vendor.

### 3. Ingestion verifies the signature and ranks the item as a claim

An item is accepted only if its signature verifies against the pinned key, the same path signed `eval.result` items use today. A verified item becomes evidence scoped to the dependent systems, ranked `vendor_attested`: above `self_reported` (questionnaire) and below `observed` (gateway, black-box eval, sign-in). An item that fails verification drops to the delivery log and is never accepted.

### 4. The export can raise reviews but not clear them

A `vendor.material_change` opens one material-change review on each dependent system, the same path the release-note feed and the black-box eval source use. A `vendor.reference_assertion` whose expiry precedes the buyer's recorded expiry shortens coverage; one claiming a longer expiry than the buyer can verify does not extend it, it opens a review. Nothing in the export closes a finding or approves a renewal.

### 5. Provenance disagreement is the highest-value signal

When `vendor.model_provenance` says the served model is unchanged but the black-box eval source flagged drift, that contradiction opens a review carrying both the attestation and the eval scores. A questionnaire cannot produce this signal, because it has no timestamp a machine can compare against an observation.

## Trust ranking

The product already ranks a form below telemetry. This RFC inserts one rank between them:

1. `observed`: gateway telemetry, black-box eval results, sign-in logs. The buyer produced it.
2. `vendor_attested`: a signed item verified against a pinned key. Not produced by the buyer, but it cannot be forged and it carries a timestamp.
3. `self_reported`: a questionnaire answer or an unsigned reference the buyer typed in.

Gates read from rank 1. Ranks 2 and 3 enrich the record and can open reviews. When two ranks disagree, the higher rank wins and the gap opens a review. No config can reorder these.

## Migration / rollout (phased, each phase shippable)

1. **Schema only.** Publish the attestation types and signing profile under `schema_version`, with a validator and no ingestion path.
2. **Buyer ingestion, pull.** Add the registry public key and feed URL, the poll, signature verification, and the `vendor_attested` rank. Wire `vendor.material_change` into the review path and `vendor.reference_assertion` into the references. No vendor-side code ships here; a buyer can test against a static signed document.
3. **Vendor export view.** On the build-side instance, add the scoped, per-customer read-only export of provenance, subprocessors, and material changes, signed with the vendor's attestation key. This is the only phase that touches the vendor side, and it ships last.
4. **Open the spec.** Once both sides speak the schema in practice, publish the profile as an open spec so a vendor can implement the export without running the platform. Owning the format is the moat, not the connector.

## Decisions (made)

- Export items rank below observations, permanently, and not by config. A gate must mean the same thing whether or not the vendor cooperates.
- The export never gates. A buyer who turns off every export still reaches every renewal decision.
- Reuse the attestation-key primitive. No new signing scheme.
- Names, dates, and hashes only. No document bodies.

## Open questions

- Feed transport: buyer-pull polling versus vendor-push upload. Pull keeps the buyer in control of when it connects; push delivers material changes faster. Phase 2 starts with pull.
- Vendor key rotation and revocation, and how a buyer is notified on rotation. The attestation-key store already models rotation for CI keys.
- Whether `vendor.reference_assertion` should require an independently checkable identifier (for example an auditor registry entry) before it can populate a reference.

## Notes on effort

Phases 1 and 2 are small: the event envelope, Ed25519 verification, the vendor registry, the references, the review path, and the delivery log are already in the tree. The cost is phase 3 on the build-side instance and keeping the spec stable enough for a third party to implement. Do not start until the vendor-independent sources ship and buyers act on them.
