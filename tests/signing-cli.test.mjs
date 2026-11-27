import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { buildSigningTranscript, computeKeyId } from "../scripts/sign-registry.mjs";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SIGN_SCRIPT = path.resolve(__dirname, "../scripts/sign-registry.mjs");

async function withTempDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agy-sign-cli-test-"));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function makeKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey,
    privateKey,
    keyId: computeKeyId(publicKey),
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function makeSampleIndex(generatedAt) {
  return {
    schemaVersion: 1,
    generatedAt,
    crawlerVersion: "1.0.0",
    scannerVersion: "1.1.0",
    totalPlugins: 0,
    plugins: [],
  };
}

function makeSampleDenylist(updatedAt) {
  return {
    schemaVersion: 1,
    updatedAt,
    blockedRepos: [],
    blockedShas: [],
  };
}

// ---------------------------------------------------------------------------
// CLI End-to-End: scripts/sign-registry.mjs
// ---------------------------------------------------------------------------
describe("scripts/sign-registry.mjs — CLI keygen and file signing", () => {
  it("--keygen emits a valid Ed25519 keypair with matching SPKI keyId", async () => {
    const { stdout } = await execFileAsync(process.execPath, [SIGN_SCRIPT, "--keygen"]);
    const keyIdMatch = stdout.match(/Key ID:\s*([a-f0-9]{16})/);
    const pubMatch = stdout.match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/);
    const privMatch = stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/);

    assert.ok(keyIdMatch, "Expected 16-char hex Key ID in --keygen output");
    assert.ok(pubMatch, "Expected SPKI public PEM in --keygen output");
    assert.ok(privMatch, "Expected PKCS8 private PEM in --keygen output");

    const pubObj = crypto.createPublicKey({ key: pubMatch[0], format: "pem" });
    const privObj = crypto.createPrivateKey({ key: privMatch[0], format: "pem" });
    assert.equal(computeKeyId(pubObj), keyIdMatch[1]);
    assert.equal(computeKeyId(crypto.createPublicKey(privObj)), keyIdMatch[1]);
  });

  it("signs index.json and denylist.json using both multiline and \\n-escaped CI secrets", async () => {
    const kp = makeKeypair();

    await withTempDir(async (publicDir) => {
      await fs.writeFile(
        path.join(publicDir, "index.json"),
        JSON.stringify(makeSampleIndex("2026-11-27T00:00:00Z"), null, 2) + "\n"
      );
      await fs.writeFile(
        path.join(publicDir, "denylist.json"),
        JSON.stringify(makeSampleDenylist("2026-11-27T00:00:00Z"), null, 2) + "\n"
      );

      for (const secretValue of [kp.privatePem, kp.privatePem.replaceAll("\n", "\\n")]) {
        await execFileAsync(process.execPath, [SIGN_SCRIPT, publicDir], {
          env: { ...process.env, REGISTRY_SIGNING_PRIVATE_KEY: secretValue },
        });

        for (const fileName of ["index.json", "denylist.json"]) {
          const rawBytes = await fs.readFile(path.join(publicDir, fileName));
          const sigEnvelope = JSON.parse(await fs.readFile(path.join(publicDir, `${fileName}.sig`), "utf8"));

          assert.equal(sigEnvelope.schemaVersion, 1);
          assert.equal(sigEnvelope.alg, "Ed25519");
          assert.equal(sigEnvelope.keyId, kp.keyId);
          assert.equal(sigEnvelope.file, fileName);
          assert.equal(Number.isNaN(Date.parse(sigEnvelope.signedAt)), false);

          const actualSha256 = crypto.createHash("sha256").update(rawBytes).digest("hex");
          assert.equal(sigEnvelope.sha256, actualSha256);

          const transcript = buildSigningTranscript({
            file: fileName,
            signedAt: sigEnvelope.signedAt,
            rawBytes,
          });
          const sigBytes = Buffer.from(sigEnvelope.signature, "base64");
          assert.equal(crypto.verify(null, transcript, kp.publicKey, sigBytes), true);
        }
      }
    });
  });

  it("fails cleanly when REGISTRY_SIGNING_PRIVATE_KEY is missing", async () => {
    await withTempDir(async (publicDir) => {
      await assert.rejects(
        () =>
          execFileAsync(process.execPath, [SIGN_SCRIPT, publicDir], {
            env: { ...process.env, REGISTRY_SIGNING_PRIVATE_KEY: "" },
          }),
        /Missing REGISTRY_SIGNING_PRIVATE_KEY/
      );
    });
  });
});
