const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Fixture = {
  name: string;
  schema: string;
  canonical_sha256?: string;
  document: Record<string, Json>;
};

const root = join(__dirname, "..");
const fixturePath = join(root, "contracts", "fixtures", "batch-0-v1.json");
const manifest = JSON.parse(readFileSync(fixturePath, "utf8"));

function canonical(value: Json): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const entries = Object.entries(value).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return `{${entries
    .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`)
    .join(",")}}`;
}

function digest(value: Json): string {
  return `sha256:${createHash("sha256").update(canonical(value), "utf8").digest("hex")}`;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertTopLevelShape(fixture: Fixture): void {
  const schema = JSON.parse(
    readFileSync(join(root, "contracts", fixture.schema), "utf8"),
  );
  const actual = Object.keys(fixture.document).sort();
  const required = [...schema.required].sort();
  assert(
    JSON.stringify(actual) === JSON.stringify(required),
    `${fixture.name}: top-level keys differ from the closed schema`,
  );
}

const hashFields = new Map<string, string>([
  ["work-context.schema.json", "context_hash"],
  ["acquisition-envelope.schema.json", "envelope_hash"],
  ["evidence-reference.schema.json", "reference_hash"],
  ["action-proposal.schema.json", "proposal_hash"],
  ["execution-permit.schema.json", "permit_hash"],
  ["execution-receipt.schema.json", "receipt_hash"],
  ["quarantine-record.schema.json", "record_hash"],
  ["legacy/action-proposal-v0.2.schema.json", "proposal_hash"],
]);

for (const fixture of manifest.positive as Fixture[]) {
  assertTopLevelShape(fixture);
  assert(
    digest(fixture.document) === fixture.canonical_sha256,
    `${fixture.name}: canonical fixture digest differs`,
  );
  const hashField = hashFields.get(fixture.schema);
  if (hashField) {
    const basis = structuredClone(fixture.document);
    const expected = basis[hashField];
    delete basis[hashField];
    assert(digest(basis) === expected, `${fixture.name}: internal hash differs`);
  }
}

for (const [schemaName, expected] of Object.entries(
  manifest.schema_digests as Record<string, string>,
)) {
  const schema = JSON.parse(
    readFileSync(join(root, "contracts", schemaName), "utf8"),
  );
  assert(digest(schema) === expected, `${schemaName}: pinned schema digest differs`);
}

const forbidden = new Set<string>(manifest.fade_forbidden_keys);
function assertFadeSafe(value: Json, path = "$fixture"): void {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertFadeSafe(child, `${path}[${index}]`));
  } else if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const normalized = key.toLowerCase().replaceAll("-", "_");
      assert(!forbidden.has(normalized), `${path}.${key}: Fade-forbidden key`);
      assertFadeSafe(child, `${path}.${key}`);
    }
  }
}

for (const fixture of manifest.positive as Fixture[]) {
  if (
    fixture.schema === "action-proposal.schema.json" ||
    fixture.schema === "execution-permit.schema.json"
  ) {
    assertFadeSafe(fixture.document);
  }
  if (fixture.schema === "weir-action-event.schema.json") {
    const serialized = canonical(fixture.document);
    for (const prohibited of ["parameters", "form_values", "raw_dom", "profile_id"]) {
      assert(!serialized.includes(`\"${prohibited}\"`), `${fixture.name}: leaked ${prohibited}`);
    }
  }
}

assert(
  manifest.integration_invariants.autowork_assignment_binding.join(",") ===
    "correlation_id,assignment_id",
  "Autowork assignment binding drifted",
);
assert(
  manifest.integration_invariants.apu_attribution.cwd_selection ===
    "unique active candidate among exact normalized-cwd matches",
  "APU unique-active attribution rule drifted",
);
assert(
  manifest.permit_clock.authority === "weir",
  "permit clock authority drifted",
);

console.log(
  `verified ${manifest.positive.length} positive fixtures and ${Object.keys(manifest.schema_digests).length} schema digests`,
);
