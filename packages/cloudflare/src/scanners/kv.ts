import type { StorageScanner, BackendScanResult } from "@ephemeral-social/verifiable-delete";
import { sha256hex } from "@ephemeral-social/verifiable-delete";

export class KVScanner implements StorageScanner {
  type = "kv";
  constructor(private kv: KVNamespace) {}

  async checkAbsence(entityId: string): Promise<BackendScanResult> {
    const hashedId = sha256hex(new TextEncoder().encode(entityId));
    const key = `entity:${hashedId}`;
    const scannedAt = new Date().toISOString();
    try {
      const value = await this.kv.get(key);
      const absent = value === null;
      return {
        type: this.type,
        identifier: key,
        query: `KV GET ${key}`,
        absent,
        scannedAt,
        note: "KV is eventually consistent; absence confirmation may be delayed up to 60 seconds.",
      };
    } catch (err) {
      return {
        type: this.type,
        identifier: key,
        query: `KV GET ${key}`,
        absent: false,
        scannedAt,
        note: `KV error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
}
