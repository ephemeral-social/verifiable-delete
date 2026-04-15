/**
 * Type declarations for @zk-kit/sparse-merkle-tree.
 * The package exports types at dist/types/ but its package.json "exports"
 * field lacks a "types" condition, so TypeScript can't resolve them.
 */
declare module "@zk-kit/sparse-merkle-tree" {
  export type Node = string | bigint;
  export type Key = Node;
  export type Value = Node;
  export type EntryMark = Node;
  export type Entry = [Key, Value, EntryMark];
  export type ChildNodes = Node[];
  export type Siblings = Node[];
  export type HashFunction = (childNodes: ChildNodes) => Node;

  export interface EntryResponse {
    entry: Entry | Node[];
    matchingEntry?: Entry | Node[];
    siblings: Siblings;
  }

  export interface MerkleProof extends EntryResponse {
    root: Node;
    membership: boolean;
  }

  export class SparseMerkleTree {
    root: Node;
    constructor(hash: HashFunction, bigNumbers?: boolean);
    get(key: Key): Value | undefined;
    add(key: Key, value: Value): void;
    update(key: Key, value: Value): void;
    delete(key: Key): void;
    createProof(key: Key): MerkleProof;
    verifyProof(merkleProof: MerkleProof): boolean;
  }
}
