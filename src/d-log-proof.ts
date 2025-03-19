import { BigInteger } from "./utils/big-Integer.ts";

export type DLogProofJSON = {
  commitment: string;
  challenge: string;
  response: string;
};

// TODO add test (not covered)
export class DLogProof {
  constructor(
    public readonly commitment: BigInteger,
    public readonly challenge: BigInteger,
    public readonly response: BigInteger,
  ) {}

  static fromJSON(data: DLogProofJSON): DLogProof {
    return new DLogProof(
      new BigInteger(data.commitment),
      new BigInteger(data.challenge),
      new BigInteger(data.response),
    );
  }

  toJSON(): DLogProofJSON {
    return {
      commitment: this.commitment.toString(),
      challenge: this.challenge.toString(),
      response: this.response.toString(),
    };
  }
}
