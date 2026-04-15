import type { StorageScanner, BackendScanResult } from "@ephemeral-social/verifiable-delete";
import { sha256hex } from "@ephemeral-social/verifiable-delete";

export class R2Scanner implements StorageScanner {
  type = "r2";
  constructor(private bucket: R2Bucket) {}

  async checkAbsence(entityId: string): Promise<BackendScanResult> {
    const hashedId = sha256hex(new TextEncoder().encode(entityId));
    const key = `entity/${hashedId}`;
    const scannedAt = new Date().toISOString();
    try {
      const head = await this.bucket.head(key);
      const absent = head === null;
      return {
        type: this.type,
        identifier: key,
        query: `R2 HEAD ${key}`,
        absent,
        scannedAt,
      };
    } catch (err) {
      return {
        type: this.type,
        identifier: key,
        query: `R2 HEAD ${key}`,
        absent: false,
        scannedAt,
        note: `R2 error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
}
