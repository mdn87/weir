# Context-bound public acquisition

Batch 1A makes `AcquisitionEnvelope`, not `WebRequest`, the public in-process broker
boundary. This is the last safe in-process shape before Batch 2 adds an authenticated
service and typed clients.

## Caller contract

`AcquisitionBroker.read`, `search`, and `enrich` accept a full
`AcquisitionEnvelope`. The envelope's `WorkContext` and `WebRequest` must validate,
`request.run_id` must equal `work_context.run_id`, and `request.request_id` must equal
`work_context.correlation_id`. A durable `CaptureStore` is also required. These checks
happen before route selection, DNS policy checks, cache I/O, or engine access.

The result contains:

- the validated acquisition envelope hash and full immutable work context;
- the context-independent `WebCapture`;
- a new `EvidenceReference` bound to the current context and request; and
- an opaque `weir-evidence:<id>` handle for the persisted reference.

A sibling must use the evidence reference, not a bare capture, as its provenance
input. The in-process result is not an authorization grant. Batch 2 still owns client
authentication and materialization access control.

## Cache and persistence behavior

Capture bodies are exact canonical JSON bytes under their SHA-256 address. Capture
manifests and evidence references are immutable files. A public cache entry may reuse
one capture across contexts because no caller identity is written into the reusable
content. Each cache hit nevertheless creates and persists a distinct evidence
reference whose `work_context_hash`, current `request_id`, and `reference_hash` differ.

Before rebinding a cache hit, WEIR compares the cached capture with its immutable
manifest and verifies the retained artifact's address, content hash, JSON encoding,
and canonical bytes. A corrupt cache record raises `CacheIntegrityError`; it is not
treated as a miss and does not trigger a silent network retry. A mismatched manifest,
artifact, or evidence reference also fails closed.

`metadata` policy references intentionally have no artifact and cannot satisfy a
materialized-content input. A stricter data-class policy may likewise persist the
reference without retaining content, as frozen in Batch 0.

## Telemetry boundary

Trace sinks accept a closed set of bounded metadata attributes: IDs, hashes, enum-like
states, sizes, durations, booleans, and reason codes. URLs, queries, page content,
adapter error text, credentials, and artifact bytes are rejected at the sink rather
than relying on every caller to remember redaction.

## Transitional CLI seam

The standalone `weir read`, `search`, and `enrich` commands temporarily use private
`_legacy_*_for_cli` methods so the CLI can remain stateless. Those methods return the
old unbound envelope and are not a sibling API. Remove them when the CLI moves to the
authenticated service client in Batch 2.

## Verification

The focused gate is:

```bash
python -m pytest -q tests/test_broker.py tests/test_persistence.py tests/test_telemetry.py
```

The repository gate remains `python -m pytest -q`. Tests cover pre-network identity
rejection, all three public methods, durable reference readback and materialization,
cache rebinding without capture duplication, cache/content/artifact tampering, and
metadata-only telemetry.
