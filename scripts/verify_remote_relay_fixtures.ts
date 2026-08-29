const { createHash, createPublicKey, verify } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Fixture = {
  name: string;
  schema: string;
  canonical_sha256: string;
  document: Record<string, Json>;
};

const root = join(__dirname, "..");
const fixturePath = join(root, "contracts", "fixtures", "remote-relay-v1.json");
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
  assert(
    JSON.stringify(Object.keys(fixture.document).sort()) ===
      JSON.stringify([...schema.required].sort()),
    `${fixture.name}: top-level keys differ from the closed schema`,
  );
}

const hashFields = new Map<string, string>([
  ["remote-decision-ack.schema.json", "acknowledgement_hash"],
  ["remote-decision-queue-state.schema.json", "record_hash"],
  ["remote-decision-revocation.schema.json", "revocation_hash"],
  ["remote-decision-audit.schema.json", "audit_hash"],
]);
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

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
  if (fixture.schema === "remote-decision-capsule.schema.json") {
    const capsule = structuredClone(fixture.document);
    const signature = capsule.signature as string;
    const keyId = capsule.key_id as string;
    delete capsule.signature;
    const rawPublicKey = Buffer.from(manifest.test_public_keys[keyId], "base64url");
    const publicKey = createPublicKey({
      key: Buffer.concat([spkiPrefix, rawPublicKey]),
      format: "der",
      type: "spki",
    });
    assert(
      verify(
        null,
        Buffer.from(canonical(capsule), "utf8"),
        publicKey,
        Buffer.from(signature, "base64url"),
      ),
      `${fixture.name}: Ed25519 signature differs`,
    );
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

for (const [flag, enabled] of Object.entries(manifest.feature_flags)) {
  assert(enabled === false, `${flag}: relay fixture flags must default off`);
}

const prohibited = [
  "parameters",
  "payload",
  "dom",
  "prompt",
  "credentials",
  "cookies",
  "profile_id",
  "permit",
];
for (const fixture of manifest.positive as Fixture[]) {
  if (
    fixture.schema === "remote-decision-capsule.schema.json" ||
    fixture.schema === "remote-decision-audit.schema.json"
  ) {
    for (const field of prohibited) {
      assert(!(field in fixture.document), `${fixture.name}: leaked ${field}`);
    }
  }
}

console.log(`verified ${manifest.positive.length} remote relay fixtures`);
