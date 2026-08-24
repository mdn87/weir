# Security Notes

## Threat model summary

WEIR crosses a hostile boundary by design. Web pages can contain malicious content, redirects, scripts, tracking, credential prompts, prompt injection, and UI designed to induce unintended actions.

The browser or reader engine must therefore be treated as an untrusted-input transport, not as a source of instructions.

## Core controls

### Domain policy

- Requests carry explicit allowed-domain constraints when practical.
- Redirects remain subject to policy.
- Public readers should reject private/internal network targets by default.
- Internal browsing requires a separate allowlisted route rather than globally disabling SSRF protections.

### Prompt injection

Page text is always data. It cannot:

- modify system or repository instructions
- grant itself new tool permissions
- expand allowed domains
- reveal credentials
- authorize an external side effect
- change retention policy

### Authentication isolation

- Profiles are identified by opaque IDs.
- Credentials are not embedded in `WebRequest`.
- Personal, business, test, and restricted profiles are isolated.
- Captures from authenticated sessions are not reused as public cache entries.

### Controller lease

One session has one active controller. A second agent or human takeover requires an explicit lease transition.

### Side effects

Side-effectful operations require typed risk classification. High-risk browser primitives such as arbitrary JS execution, file upload, purchase, account mutation, sending, deletion, and submission must not be treated as ordinary clicks.

### Artifact retention

Raw HTML, screenshots, HAR bodies, downloaded documents, and rendered DOMs may contain sensitive material. Store them under an explicit artifact/retention policy and keep ordinary telemetry metadata-only by default.

### Engine supply chain

- Pin engine versions in managed deployments.
- Record engine versions in captures and benchmark results.
- Prefer managed worker images over unbounded `npx --yes` execution in production.
- Track security posture of external browser dependencies.

#### Audit snapshot (2026-08-24, benchmark host)

Both candidate engines were license- and supply-chain-reviewed before the
first benchmark; the full record (hashes, endpoints, workarounds) lives in the
host-local external-tools manifest, outside this repo.

- `@only-cli/oc` 0.4.0 (MIT): npm audit clean. The upstream repo was six days
  old at audit time with a single pseudonymous owner — pin the version and
  re-review on every upgrade. Normal reads contact only the target URL; its
  `impers` dependency reaches `api.impersonate.pro` solely on explicit
  `impers update`/`config`. Its transport spoofs browser TLS fingerprints
  (curl-impersonate), which is dual-use: domain policy must decide where
  fingerprint evasion is acceptable rather than treating it as a free default.
- `agent-browser` 0.34.0 (Apache-2.0, vercel-labs): npm audit clean, zero
  runtime npm deps, no telemetry found in the JS layer. postinstall fetches a
  platform-native binary from versioned upstream GitHub releases. Its
  persistent daemon binds 127.0.0.1 only, but outlives CLI calls and shares a
  default session across reads until the adapter passes `--session` isolation.

## `oc` integration caution

`oc` has useful private/internal-address blocking. WEIR should preserve that default for public acquisition. Internal services should use an explicit internal adapter or browser worker with its own allowlist.

## Browser profile caution

A browser profile can represent broad ambient authority even before a click occurs. Profile eligibility must therefore be part of policy and worker placement, not a convenience option exposed to arbitrary seats.
