import type { StorageScanner, BackendScanResult } from "@ephemeral-social/verifiable-delete";

export class D1Scanner implements StorageScanner {
  type = "d1";
  constructor(private db: D1Database, private table = "demo_data") {}

  async checkAbsence(entityId: string): Promise<BackendScanResult> {
    const scannedAt = new Date().toISOString();
    try {
      const result = await this.db.prepare(`SELECT COUNT(*) as count FROM ${this.table} WHERE entity_id = ?`)
        .bind(entityId)
        .first<{ count: number }>();
      const absent = result?.count === 0;
      return {
        type: this.type,
        identifier: this.table,
        query: `SELECT COUNT(*) FROM ${this.table} WHERE entity_id = ?`,
        absent,
        scannedAt,
        ...(absent ? {} : { note: "Data still present. Note: D1 Time Travel may retain historical data for up to 30 days." }),
      };
    } catch (err) {
      return {
        type: this.type,
        identifier: this.table,
        query: `SELECT COUNT(*) FROM ${this.table} WHERE entity_id = ?`,
        absent: false,
        scannedAt,
        note: `D1 query error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
}
