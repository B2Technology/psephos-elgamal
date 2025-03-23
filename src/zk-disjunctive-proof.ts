import type { ZKProofJSON } from "./zk-proof.ts";
import { ZKProof } from "./zk-proof.ts";

export type ZKDisjunctiveProofJSON = {
  proofs: ZKProofJSON[];
};

export class ZKDisjunctiveProof {
  constructor(public readonly proofs: ZKProof[]) {}

  static fromJsonProofs(data: ZKProofJSON[]): ZKDisjunctiveProof {
    if (!data || !Array.isArray(data)) {
      throw new Error("Invalid proofs! Expected an array of ZKProofJSON");
    }

    const proofs = data.map((d) => ZKProof.fromJSON(d));

    return new ZKDisjunctiveProof(proofs);
  }

  toProofsJSON(): ZKProofJSON[] {
    return this.proofs.map((p) => p.toJSON());
  }

  toJSON(): ZKDisjunctiveProofJSON {
    return {
      proofs: this.toProofsJSON(),
    };
  }
}
