/**
 * KeyShareDO — Durable Object for threshold key share storage.
 *
 * Each DO instance holds one share holder's key material:
 * - An Ed25519 keypair (generated once, persisted in SQLite)
 * - Shares indexed by KEK ID
 * - Destruction attestation signing on share deletion
 *
 * @module key-share
 */

import { DurableObject } from "cloudflare:workers";
import type { ShareHolder, SerializedDestructionAttestation } from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";
import { KeyShareStorage } from "./key-share-storage.js";

export { KeyShareStorage, type SqlStorageLike } from "./key-share-storage.js";

export class KeyShareDO extends DurableObject<Env> {
  private storage: KeyShareStorage | null = null;

  private getStorage(): KeyShareStorage {
    if (!this.storage) {
      this.storage = new KeyShareStorage(this.ctx.storage.sql);
    }
    return this.storage;
  }

  async getOrCreateKeypair(): Promise<{ publicKey: string }> {
    const { publicKey } = await this.getStorage().getOrCreateKeypair();
    return { publicKey };
  }

  async getPublicKey(): Promise<string> {
    return this.getStorage().getPublicKey();
  }

  async getShareHolder(label: string): Promise<ShareHolder> {
    return this.getStorage().getShareHolder(label);
  }

  async storeShare(kekId: string, shareIndex: number, shareData: Uint8Array): Promise<void> {
    return this.getStorage().storeShare(kekId, shareIndex, shareData);
  }

  async destroyShare(kekId: string, holderLabel: string): Promise<SerializedDestructionAttestation> {
    return this.getStorage().destroyShare(kekId, holderLabel);
  }

  async hasShare(kekId: string): Promise<boolean> {
    return this.getStorage().hasShare(kekId);
  }

}
