// ---------------------------------------------------------------------------
// Web Crypto Native Ed25519 Verification (Matches scripts/sign-registry.mjs)
// ---------------------------------------------------------------------------
const SIGNING_DOMAIN = "agy-registry-sig-v1";

/**
 * Pin one or more Ed25519 SPKI public keys keyed by 16-char hex SPKI SHA-256 fingerprint.
 * Keep both old and new keys here during key rotation for zero-downtime transitions.
 */
export const TRUSTED_PUBLIC_KEYS = {
  "39619f51b6d74dfa": `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAmuOzO8i/I8liWn2Vk1wY3PAWXciq/yQOaeiU4OfonTg=
-----END PUBLIC KEY-----`,
};

export async function sha256Hex(arrayBuffer) {
  const digest = await crypto.subtle.digest("SHA-256", arrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(b64) {
  const bin = atob(String(b64 || "").replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function pemToSpkiDer(pem) {
  const stripped = String(pem || "")
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, "")
    .replace(/-----END [A-Z0-9 ]+-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

function buildSigningTranscript({ file, signedAt, rawBytes }) {
  const prefix = new TextEncoder().encode(`${SIGNING_DOMAIN}\0${file}\0${signedAt}\0`);
  const out = new Uint8Array(prefix.length + rawBytes.length);
  out.set(prefix, 0);
  out.set(rawBytes, prefix.length);
  return out;
}

export async function importTrustedEd25519Keys() {
  const keyMap = new Map();
  for (const [declaredId, pem] of Object.entries(TRUSTED_PUBLIC_KEYS)) {
    if (!pem || !pem.trim()) continue;
    const spkiDer = pemToSpkiDer(pem);
    const derivedId = (await sha256Hex(spkiDer)).slice(0, 16);
    if (declaredId !== derivedId) {
      throw new Error(`Misconfigured public keyId "${declaredId}" (expected "${derivedId}").`);
    }
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      spkiDer,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    keyMap.set(derivedId, cryptoKey);
  }
  return keyMap;
}

export async function verifyDetachedEd25519({ fileName, rawBuf, sigEnvelope, keyMap }) {
  if (!sigEnvelope || typeof sigEnvelope !== "object") {
    throw new Error(`Malformed ${fileName}.sig envelope.`);
  }
  if (sigEnvelope.schemaVersion !== 1 || sigEnvelope.alg !== "Ed25519") {
    throw new Error(`Unsupported signature algorithm "${sigEnvelope.alg}" in ${fileName}.sig.`);
  }
  if (sigEnvelope.file !== fileName) {
    throw new Error(`Cross-file replay rejected: signature issued for "${sigEnvelope.file}", not "${fileName}".`);
  }
  if (Number.isNaN(Date.parse(sigEnvelope.signedAt))) {
    throw new Error(`Invalid signedAt timestamp in ${fileName}.sig.`);
  }

  const publicKey = keyMap.get(sigEnvelope.keyId);
  if (!publicKey) {
    throw new Error(`Untrusted registry signing keyId "${sigEnvelope.keyId}".`);
  }

  const actualSha256 = await sha256Hex(rawBuf);
  if (sigEnvelope.sha256 !== actualSha256) {
    throw new Error(`SHA-256 digest mismatch for ${fileName}.`);
  }

  const rawBytes = new Uint8Array(rawBuf);
  const sigBytes = base64ToBytes(sigEnvelope.signature);
  const transcript = buildSigningTranscript({
    file: fileName,
    signedAt: sigEnvelope.signedAt,
    rawBytes,
  });

  const valid = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, sigBytes, transcript);
  if (!valid) {
    throw new Error(`Cryptographic Ed25519 signature verification failed for ${fileName}.`);
  }

  return { keyId: sigEnvelope.keyId, signedAt: sigEnvelope.signedAt };
}
