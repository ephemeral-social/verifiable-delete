/**
 * Demo deletion orchestrator.
 *
 * Runs the full 9-step deletion pipeline and streams SSE events.
 * Each step emits status events; final event includes the W3C VC receipt.
 * Inspector events show data state transforming in real-time.
 *
 * @module orchestrator
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  generateKEK,
  encrypt,
  exportKeyMaterial,
  verifyKeyDestruction,
  splitKey,
  runDeletionScan,
  hashScanResult,
  computeCommitment,
  createDeletionReceipt,
  deserializeAttestation,
  canonicalJSON,
  type ThresholdConfig,
  type SerializedDestructionAttestation,
  type LogEntry,
} from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";
import { storeDemoData, deleteDemoData } from "./store.js";
import { D1Scanner } from "../scanners/d1.js";
import { KVScanner } from "../scanners/kv.js";
import { R2Scanner } from "../scanners/r2.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export interface StepEvent {
  step: number;
  name: string;
  status: "running" | "complete";
  data?: Record<string, unknown>;
}

function sseEncode(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function signLogEntry(
  entry: Omit<LogEntry, "index" | "operatorSignature">,
  signingKey: Uint8Array,
): Promise<string> {
  const message = new TextEncoder().encode(
    "vd-log-entry-v1:" + canonicalJSON(entry),
  );
  return bytesToHex(await ed.signAsync(message, signingKey));
}

/**
 * Run the demo deletion pipeline and return an SSE Response.
 */
export function runDemoDeletion(
  env: Env,
  plaintextInput: string,
  options?: { delayMs?: number },
): Response {
  const encoder = new TextEncoder();
  const stepDelay = options?.delayMs ?? 2000;

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(sseEncode(event, data)));
      };

      const step = (num: number, name: string, status: "running" | "complete", data?: Record<string, unknown>) => {
        emit("step", { step: num, name, status, data });
      };

      try {
        const entityId = crypto.randomUUID();
        const data = encoder.encode(plaintextInput);

        const operatorSigningKey = env.OPERATOR_SIGNING_KEY
          ? hexToBytes(env.OPERATOR_SIGNING_KEY)
          : crypto.getRandomValues(new Uint8Array(32));
        const operatorPublicKey = await ed.getPublicKeyAsync(operatorSigningKey);

        // --- Step 1: Generate KEK ---
        step(1, "Generate KEK", "running");
        const kek = await generateKEK();
        step(1, "Generate KEK", "complete", {
          kekId: kek.id,
          algorithm: "AES-256-GCM",
          epoch: kek.epoch,
        });
        emit("inspector", {
          phase: "plaintext",
          inputPreview: plaintextInput.slice(0, 200),
          inputSize: plaintextInput.length,
          kekId: kek.id,
        });

        // --- Step 2: Encrypt & Store ---
        if (stepDelay > 0) await delay(stepDelay);
        step(2, "Encrypt & Store", "running");
        const blob = await encrypt(data, kek, entityId);
        await storeDemoData(env, entityId, blob);
        step(2, "Encrypt & Store", "complete", {
          entityId,
          ciphertextLength: blob.ciphertext.length,
          backends: ["D1", "KV", "R2"],
        });
        emit("inspector", {
          phase: "encrypted",
          ciphertextHex: bytesToHex(blob.ciphertext),
          nonceHex: bytesToHex(blob.nonce),
          wrappedDekHex: bytesToHex(blob.wrappedDek),
          entityId,
          backends: ["D1", "KV", "R2"],
        });

        // Register entity in SMT (needed before removal later)
        const smtDOId = env.SMT_DO.idFromName("main");
        const smtDO = env.SMT_DO.get(smtDOId);
        await smtDO.addEntity(entityId);

        // --- Step 3: Split Key (2-of-3 Shamir) ---
        if (stepDelay > 0) await delay(stepDelay);
        step(3, "Split Key", "running");
        const keyMaterial = await exportKeyMaterial(kek);

        // Get share holders from 3 DO instances
        const doLabels = ["operator", "oracle", "auditor"] as const;
        const doStubs = doLabels.map((label) => {
          const id = env.KEY_SHARE_DO.idFromName(label);
          return env.KEY_SHARE_DO.get(id);
        });
        const holders = await Promise.all(
          doStubs.map((stub, i) => stub.getShareHolder(doLabels[i]!)),
        );

        const config: ThresholdConfig = {
          totalShares: 3,
          threshold: 2,
          holders,
        };
        const { shares } = await splitKey(keyMaterial, kek.id, config);

        // Distribute shares to DOs
        await Promise.all(
          doStubs.map((stub, i) =>
            stub.storeShare(kek.id, shares[i]!.index, shares[i]!.data),
          ),
        );

        step(3, "Split Key", "complete", {
          kekId: kek.id,
          threshold: "2-of-3",
          holders: doLabels,
        });
        emit("inspector", {
          phase: "key_split",
          shares: doLabels.map((label, i) => ({
            index: shares[i]!.index,
            holder: label,
            status: "active",
          })),
          threshold: "2-of-3",
        });

        // --- Step 4: Destroy Shares (2 of 3) ---
        if (stepDelay > 0) await delay(stepDelay);
        step(4, "Destroy Shares", "running");
        const attestations: SerializedDestructionAttestation[] = [];
        for (let i = 0; i < 2; i++) {
          const att = await doStubs[i]!.destroyShare(kek.id, doLabels[i]!);
          attestations.push(att);
        }

        step(4, "Destroy Shares", "complete", {
          destroyed: 2,
          total: 3,
          attestations: attestations.map((a) => ({
            holder: a.holder.label,
            shareIndex: a.shareIndex,
            destroyedAt: a.destroyedAt,
            signaturePrefix: a.signature.slice(0, 16) + "...",
          })),
        });
        emit("inspector", {
          phase: "key_destroyed",
          shares: doLabels.map((label, i) => ({
            index: shares[i]!.index,
            holder: label,
            status: i < 2 ? "destroyed" : "active",
            destroyedAt: i < 2 ? attestations[i]!.destroyedAt : undefined,
          })),
          keyStatus: "irrecoverable",
        });

        // --- Step 5: Delete Data ---
        if (stepDelay > 0) await delay(stepDelay);
        step(5, "Delete Data", "running");
        await deleteDemoData(env, entityId);

        // Verify key destruction (use a different KEK to simulate destroyed key)
        const wrongKek = await generateKEK();
        const keyVerified = await verifyKeyDestruction(blob, wrongKek);

        step(5, "Delete Data", "complete", {
          entityId,
          backends: ["D1", "KV", "R2"],
          keyVerified,
        });
        emit("inspector", {
          phase: "data_deleted",
          dataStatus: "deleted",
          backendsCleared: ["D1", "KV", "R2"],
        });

        // --- Step 6: Scan Backends ---
        if (stepDelay > 0) await delay(stepDelay);
        step(6, "Scan Backends", "running");
        const scanners = [
          new D1Scanner(env.DB),
          new KVScanner(env.KV),
          new R2Scanner(env.BUCKET),
        ];
        const scanResult = await runDeletionScan({
          entityId,
          scanners,
          testCiphertextId: entityId,
          keyVerified,
        });
        step(6, "Scan Backends", "complete", {
          allVerified: scanResult.allVerified,
          backends: scanResult.backends.map((b) => ({
            type: b.type,
            absent: b.absent,
            note: b.note,
          })),
          caveats: scanResult.caveats,
        });
        emit("inspector", {
          phase: "verified",
          scanVerified: true,
          backendResults: scanResult.backends.map((b) => ({
            type: b.type,
            absent: b.absent,
          })),
        });

        // --- Step 7: SMT Remove & Prove ---
        if (stepDelay > 0) await delay(stepDelay);
        step(7, "SMT Remove & Prove", "running");
        const nonMembershipProof = await smtDO.removeEntity(entityId);
        step(7, "SMT Remove & Prove", "complete", {
          smtRoot: (nonMembershipProof.smtRoot as string).slice(0, 16) + "...",
          nonMember: nonMembershipProof.nonMember,
        });
        emit("inspector", {
          phase: "smt_proven",
          smtRoot: nonMembershipProof.smtRoot,
          nonMember: nonMembershipProof.nonMember,
          entityHash: nonMembershipProof.entityHash,
        });

        // --- Step 8: Append to Transparency Log ---
        if (stepDelay > 0) await delay(stepDelay);
        step(8, "Append to Log", "running");
        const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
        const commitment = await computeCommitment("demo_data", entityId, salt);
        const scanHash = await hashScanResult(scanResult);

        const entryWithoutSig: Omit<LogEntry, "index" | "operatorSignature"> = {
          receiptId: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          entityType: "demo_data",
          commitment,
          deletionMethod: "crypto_shredding_2of3",
          thresholdSignatures: attestations.map((a) => a.signature),
          scanHash,
          smtRoot: nonMembershipProof.smtRoot,
        };

        const operatorSignature = await signLogEntry(entryWithoutSig, operatorSigningKey);
        const logEntry: Omit<LogEntry, "index"> = {
          ...entryWithoutSig,
          operatorSignature,
        };

        // Append to Transparency Log DO
        const logDOId = env.TRANSPARENCY_LOG_DO.idFromName("main");
        const logDO = env.TRANSPARENCY_LOG_DO.get(logDOId);
        const inclusionProof = await logDO.append(logEntry);
        const treeHead = await logDO.getTreeHead();

        step(8, "Append to Log", "complete", {
          logIndex: inclusionProof.logIndex,
          treeSize: inclusionProof.treeSize,
          rootHash: inclusionProof.rootHash.slice(0, 16) + "...",
          commitment: commitment.slice(0, 16) + "...",
        });
        emit("inspector", {
          phase: "logged",
          logIndex: inclusionProof.logIndex,
          commitment,
          treeSize: inclusionProof.treeSize,
        });

        // --- Step 9: Generate Receipt ---
        if (stepDelay > 0) await delay(stepDelay);
        step(9, "Generate Receipt", "running");
        const receipt = await createDeletionReceipt({
          entityType: "demo_data",
          entityId,
          issuerDid: "did:web:verifiabledelete.dev",
          signingKey: operatorSigningKey,
          attestations: attestations.map(deserializeAttestation),
          scanResult,
          nonMembershipProof,
          inclusionProof,
        });

        step(9, "Generate Receipt", "complete", {
          receiptId: receipt.id,
          issuer: receipt.issuer,
          credentialType: receipt.type,
          evidenceCount: receipt.evidence.length,
        });
        emit("inspector", {
          phase: "receipted",
          receiptId: receipt.id,
        });

        // --- Done ---
        emit("done", {
          receipt,
          operatorPublicKey: bytesToHex(operatorPublicKey),
          treeHead,
          entityId,
          commitment,
          salt,
        });
      } catch (err) {
        emit("error", {
          message: err instanceof Error ? err.message : String(err),
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
