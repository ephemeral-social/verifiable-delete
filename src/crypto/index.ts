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

// --- Functions (stubs, implementation follows) ---

/**
 * Generate a new KEK (Key Encryption Key).
 * Uses crypto.getRandomValues() for key material.
 */
export async function generateKEK(): Promise<VDKey> {
  throw new Error("Not implemented");
}

/**
 * Generate a random DEK and encrypt data.
 * Each DEK is used exactly once (eliminates nonce reuse risk).
 */
export async function encrypt(
  _data: Uint8Array,
  _kek: VDKey,
  _entityId: string,
): Promise<EncryptedBlob> {
  throw new Error("Not implemented");
}

/**
 * Decrypt an encrypted blob using the KEK to unwrap the DEK.
 */
export async function decrypt(
  _blob: EncryptedBlob,
  _kek: VDKey,
): Promise<Uint8Array> {
  throw new Error("Not implemented");
}

/**
 * Ratchet the KEK forward one epoch.
 * Derives next KEK from current KEK + fresh randomness via HKDF-SHA256.
 * The caller MUST delete the old key after ratcheting.
 */
export async function ratchetKey(_currentKey: VDKey): Promise<RatchetResult> {
  throw new Error("Not implemented");
}

/**
 * Attempt decryption with a (presumably destroyed) key.
 * Returns true if decryption fails as expected (key is destroyed).
 * Returns false if decryption succeeds (key was NOT destroyed, this is bad).
 */
export async function verifyKeyDestruction(
  _testCiphertext: EncryptedBlob,
  _kek: VDKey,
): Promise<boolean> {
  throw new Error("Not implemented");
}

/**
 * Serialize a VDKey for storage. Extracts raw key material.
 * Only use for threshold splitting, never for long-term storage.
 */
export async function exportKeyMaterial(_kek: VDKey): Promise<Uint8Array> {
  throw new Error("Not implemented");
}

/**
 * Reconstruct a VDKey from raw key material.
 */
export async function importKeyMaterial(
  _material: Uint8Array,
  _id: string,
  _epoch: number,
): Promise<VDKey> {
  throw new Error("Not implemented");
}
