import { bytesToHex } from "@noble/hashes/utils";
import type { EncryptedBlob } from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";

/**
 * Store encrypted demo data to D1, KV, and R2 in parallel.
 */
export async function storeDemoData(
  env: Env,
  entityId: string,
  blob: EncryptedBlob,
): Promise<void> {
  const hexBlob = bytesToHex(blob.ciphertext);
  const hexNonce = bytesToHex(blob.nonce);
  const hexWrappedDek = bytesToHex(blob.wrappedDek);

  await Promise.all([
    // D1
    env.DB.prepare(
      "INSERT OR REPLACE INTO demo_data (entity_id, encrypted_blob, nonce, wrapped_dek, kek_id) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(entityId, hexBlob, hexNonce, hexWrappedDek, blob.kekId)
      .run(),

    // KV
    env.KV.put(
      `entity:${entityId}`,
      JSON.stringify({
        encrypted_blob: hexBlob,
        nonce: hexNonce,
        wrapped_dek: hexWrappedDek,
        kek_id: blob.kekId,
      }),
    ),

    // R2
    env.BUCKET.put(`entity/${entityId}`, blob.ciphertext),
  ]);
}

/**
 * Delete demo data from D1, KV, and R2 in parallel.
 */
export async function deleteDemoData(
  env: Env,
  entityId: string,
): Promise<void> {
  await Promise.all([
    // D1
    env.DB.prepare("DELETE FROM demo_data WHERE entity_id = ?")
      .bind(entityId)
      .run(),

    // KV
    env.KV.delete(`entity:${entityId}`),

    // R2
    env.BUCKET.delete(`entity/${entityId}`),
  ]);
}
