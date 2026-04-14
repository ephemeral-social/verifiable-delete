/**
 * Minimal Web Crypto API type declarations.
 *
 * tsconfig has `"types": []` and `"lib": ["ES2022"]` which excludes DOM/WebWorker
 * ambient types. Node >=18 provides Web Crypto at runtime via globalThis.crypto.
 * This shim provides the type information tsc needs.
 */

/* eslint-disable @typescript-eslint/no-empty-object-type */

interface Algorithm {
  name: string;
}

interface AesKeyGenParams extends Algorithm {
  length: number;
}

interface AesGcmParams extends Algorithm {
  iv: BufferSource;
  additionalData?: BufferSource;
  tagLength?: number;
}

interface HkdfParams extends Algorithm {
  hash: string;
  salt: BufferSource;
  info: BufferSource;
}

type AlgorithmIdentifier = Algorithm | string;
type BufferSource = ArrayBufferView | ArrayBuffer;
type KeyFormat = "jwk" | "pkcs8" | "raw" | "spki";
type KeyType = "private" | "public" | "secret";
type KeyUsage =
  | "decrypt"
  | "deriveBits"
  | "deriveKey"
  | "encrypt"
  | "sign"
  | "unwrapKey"
  | "verify"
  | "wrapKey";

interface CryptoKey {
  readonly algorithm: Algorithm;
  readonly extractable: boolean;
  readonly type: KeyType;
  readonly usages: KeyUsage[];
}

interface SubtleCrypto {
  decrypt(
    algorithm: AlgorithmIdentifier | AesGcmParams,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  deriveBits(
    algorithm: AlgorithmIdentifier | HkdfParams,
    baseKey: CryptoKey,
    length: number,
  ): Promise<ArrayBuffer>;
  encrypt(
    algorithm: AlgorithmIdentifier | AesGcmParams,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  exportKey(format: "raw", key: CryptoKey): Promise<ArrayBuffer>;
  importKey(
    format: KeyFormat,
    keyData: BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm: AlgorithmIdentifier,
    unwrappedKeyAlgorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm: AlgorithmIdentifier,
  ): Promise<ArrayBuffer>;
}

interface Crypto {
  readonly subtle: SubtleCrypto;
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  randomUUID(): `${string}-${string}-${string}-${string}-${string}`;
}

declare const crypto: Crypto;

// TextEncoder/TextDecoder — part of the Encoding API, not in ES2022 lib
interface TextEncoder {
  encode(input?: string): Uint8Array;
  readonly encoding: string;
}
interface TextDecoder {
  decode(input?: BufferSource, options?: { stream?: boolean }): string;
  readonly encoding: string;
}
declare var TextEncoder: {
  new (): TextEncoder;
  prototype: TextEncoder;
};
declare var TextDecoder: {
  new (label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean }): TextDecoder;
  prototype: TextDecoder;
};

// btoa — used for base64 encoding (available globally in Node 16+)
declare function btoa(data: string): string;
