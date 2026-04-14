/**
 * Envelope encryption (AES-256-GCM, DEK/KEK) with forward-secret key ratcheting (HKDF).
 *
 * Platform-agnostic: depends only on Web Crypto API (globalThis.crypto.subtle).
 *
 * @module crypto
 */

// --- Types ---

/** A 256-bit key represented as a CryptoKey (non-extractable by default). */
export interface VDKey {
  /** The Web Crypto CryptoKey handle. */
  cryptoKey: CryptoKey;
  /** Key identifier (random UUID). */
  id: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** Epoch counter for ratcheting. */
  epoch: number;
}

/** Encrypted data blob with metadata needed for decryption. */
export interface EncryptedBlob {
  /** AES-256-GCM ciphertext (includes authentication tag). */
  ciphertext: Uint8Array;
  /** 96-bit random nonce used for this encryption. */
  nonce: Uint8Array;
  /** The wrapped DEK (encrypted with KEK via AES-KW). */
  wrappedDek: Uint8Array;
  /** Entity identifier this blob belongs to. */
  entityId: string;
  /** KEK identifier used to wrap the DEK. */
  kekId: string;
}

/** Result of a key ratchet step. */
export interface RatchetResult {
  /** The new KEK for the next epoch. */
  nextKey: VDKey;
  /** The epoch number of the new key. */
  epoch: number;
}

// --- Functions ---

/**
 * Generate a new KEK (Key Encryption Key).
 * Uses crypto.getRandomValues() for key material.
 */
export async function generateKEK(): Promise<VDKey> {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    "AES-KW",
    true,
    ["wrapKey", "unwrapKey"],
  );
  return {
    cryptoKey,
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    epoch: 0,
  };
}

/**
 * Generate a random DEK and encrypt data.
 * Each DEK is used exactly once (eliminates nonce reuse risk).
 */
export async function encrypt(
  data: Uint8Array,
  kek: VDKey,
  entityId: string,
): Promise<EncryptedBlob> {
  // Generate a fresh DEK
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const dek = await crypto.subtle.importKey(
    "raw",
    rawDek,
    "AES-GCM",
    true,
    ["encrypt"],
  );

  // Random nonce (96-bit)
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt data with DEK
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, dek, data),
  );

  // Wrap DEK with KEK
  const wrappedDek = new Uint8Array(
    await crypto.subtle.wrapKey("raw", dek, kek.cryptoKey, "AES-KW"),
  );

  return {
    ciphertext,
    nonce,
    wrappedDek,
    entityId,
    kekId: kek.id,
  };
}

/**
 * Decrypt an encrypted blob using the KEK to unwrap the DEK.
 */
export async function decrypt(
  blob: EncryptedBlob,
  kek: VDKey,
): Promise<Uint8Array> {
  // Unwrap the DEK using the KEK
  const dek = await crypto.subtle.unwrapKey(
    "raw",
    blob.wrappedDek,
    kek.cryptoKey,
    "AES-KW",
    "AES-GCM",
    false,
    ["decrypt"],
  );

  // Decrypt the ciphertext with the unwrapped DEK
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.nonce },
    dek,
    blob.ciphertext,
  );

  return new Uint8Array(plaintext);
}

/**
 * Ratchet the KEK forward one epoch.
 * Derives next KEK from current KEK + fresh randomness via HKDF-SHA256.
 * The caller MUST delete the old key after ratcheting.
 */
export async function ratchetKey(currentKey: VDKey): Promise<RatchetResult> {
  // Export current key material
  const currentKeyMaterial = new Uint8Array(
    await crypto.subtle.exportKey("raw", currentKey.cryptoKey),
  );

  // Generate fresh randomness
  const freshRandom = crypto.getRandomValues(new Uint8Array(32));

  // Concatenate into 64-byte IKM
  const ikm = new Uint8Array(64);
  ikm.set(currentKeyMaterial, 0);
  ikm.set(freshRandom, 32);

  // Import as HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const nextEpoch = currentKey.epoch + 1;
  const encoder = new TextEncoder();
  const salt = encoder.encode(String(nextEpoch));
  const info = encoder.encode("vd-kek-ratchet-v1");

  // Derive new key material
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    hkdfKey,
    256,
  );

  // Zero out sensitive material (best-effort)
  ikm.fill(0);
  currentKeyMaterial.fill(0);

  // Import derived bits as new KEK
  const nextKey = await importKeyMaterial(
    new Uint8Array(derivedBits),
    crypto.randomUUID(),
    nextEpoch,
  );

  return { nextKey, epoch: nextEpoch };
}

/**
 * Attempt decryption with a (presumably destroyed) key.
 * Returns true if decryption fails as expected (key is destroyed).
 * Returns false if decryption succeeds (key was NOT destroyed, this is bad).
 */
export async function verifyKeyDestruction(
  testCiphertext: EncryptedBlob,
  kek: VDKey,
): Promise<boolean> {
  try {
    await decrypt(testCiphertext, kek);
    return false; // Decryption succeeded — key was NOT destroyed
  } catch {
    return true; // Decryption failed — key is destroyed
  }
}

/**
 * Serialize a VDKey for storage. Extracts raw key material.
 * Only use for threshold splitting, never for long-term storage.
 */
export async function exportKeyMaterial(kek: VDKey): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.exportKey("raw", kek.cryptoKey),
  );
}

/**
 * Reconstruct a VDKey from raw key material.
 */
export async function importKeyMaterial(
  material: Uint8Array,
  id: string,
  epoch: number,
): Promise<VDKey> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    material,
    "AES-KW",
    true,
    ["wrapKey", "unwrapKey"],
  );
  return {
    cryptoKey,
    id,
    createdAt: new Date().toISOString(),
    epoch,
  };
}
