/**
 * Generate an Ed25519 operator signing key pair for Verifiable Delete.
 *
 * Usage: npx tsx packages/cloudflare/scripts/generate-operator-key.ts
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

async function main() {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const privateHex = bytesToHex(privateKey);
  const publicHex = bytesToHex(publicKey);

  console.log("=== Verifiable Delete — Operator Signing Key ===\n");
  console.log(`Private key (hex): ${privateHex}`);
  console.log(`Public key  (hex): ${publicHex}\n`);
  console.log("Set the secret in Cloudflare Workers:\n");
  console.log(`  echo "${privateHex}" | npx wrangler secret put OPERATOR_SIGNING_KEY\n`);
}

main().catch(console.error);
