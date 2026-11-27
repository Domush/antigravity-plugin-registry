#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SIGNING_DOMAIN = "agy-registry-sig-v1";
const FILES_TO_SIGN = ["index.json", "denylist.json"];

/**
 * Compute the 16-char hex SPKI SHA-256 fingerprint for an Ed25519 public key.
 */
export function computeKeyId(publicKey) {
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spkiDer).digest("hex").slice(0, 16);
}

/**
 * Build the domain-separated signing transcript over raw file bytes.
 */
export function buildSigningTranscript({ file, signedAt, rawBytes }) {
  return Buffer.concat([
    Buffer.from(`${SIGNING_DOMAIN}\0${file}\0${signedAt}\0`, "utf8"),
    rawBytes,
  ]);
}

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyId = computeKeyId(publicKey);
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });

  console.log(`=== Generated Ed25519 Registry Keypair ===`);
  console.log(`Key ID: ${keyId}\n`);
  console.log(`1) Embed this PUBLIC key in server/lib/catalog.mjs (TRUSTED_PUBLIC_KEYS["${keyId}"]):`);
  console.log(publicPem);
  console.log(`2) Store this PRIVATE key as GitHub Actions secret REGISTRY_SIGNING_PRIVATE_KEY:`);
  console.log(privatePem);
}

function loadPrivateKeyFromEnv() {
  const raw = process.env.REGISTRY_SIGNING_PRIVATE_KEY || "";
  if (!raw.trim()) {
    throw new Error("Missing REGISTRY_SIGNING_PRIVATE_KEY environment variable.");
  }
  // Support both multiline PEM and single-line \n-escaped PEM in CI secrets
  const pem = raw.includes("\\n") ? raw.replaceAll("\\n", "\n") : raw;
  return crypto.createPrivateKey({ key: pem, format: "pem" });
}

async function signFile({ publicDir, fileName, privateKey, publicKey, keyId }) {
  const targetPath = path.join(publicDir, fileName);
  const sigPath = `${targetPath}.sig`;
  const rawBytes = await fs.readFile(targetPath);

  // Confirm valid JSON before signing
  JSON.parse(rawBytes.toString("utf8"));

  const signedAt = new Date().toISOString();
  const sha256 = crypto.createHash("sha256").update(rawBytes).digest("hex");
  const transcript = buildSigningTranscript({ file: fileName, signedAt, rawBytes });

  // Ed25519 uses `null` as the digest algorithm in Node.js crypto
  const sigBytes = crypto.sign(null, transcript, privateKey);

  // Immediate self-verification before writing the detached envelope
  const verified = crypto.verify(null, transcript, publicKey, sigBytes);
  if (!verified) {
    throw new Error(`Self-verification failed after signing ${fileName}`);
  }

  const envelope = {
    schemaVersion: 1,
    alg: "Ed25519",
    keyId,
    file: fileName,
    signedAt,
    sha256,
    signature: sigBytes.toString("base64"),
  };

  await fs.writeFile(sigPath, JSON.stringify(envelope, null, 2) + "\n", "utf8");
  console.log(`[sign] Signed ${fileName} -> ${fileName}.sig (keyId=${keyId}, sha256=${sha256.slice(0, 12)}...)`);
}

async function main() {
  const arg = process.argv[2];
  if (arg === "--keygen") {
    generateKeypair();
    return;
  }

  const publicDir = path.resolve(arg || "./registry-data/public");
  const privateKey = loadPrivateKeyFromEnv();
  const publicKey = crypto.createPublicKey(privateKey);
  const keyId = computeKeyId(publicKey);

  for (const fileName of FILES_TO_SIGN) {
    await signFile({ publicDir, fileName, privateKey, publicKey, keyId });
  }
}

const isDirectRun =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  main().catch((err) => {
    console.error("[sign] Fatal:", err.message);
    process.exitCode = 1;
  });
}
