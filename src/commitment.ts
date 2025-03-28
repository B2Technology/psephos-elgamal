import { BigInteger } from "./utils/index.ts";

export type CommitmentJSON = {
  A: string;
  B: string;
};

export class Commitment {
  constructor(
    public readonly A: BigInteger,
    public readonly B: BigInteger,
  ) {}

  static fromJSON(data: CommitmentJSON): Commitment {
    return new Commitment(new BigInteger(data.A), new BigInteger(data.B));
  }

  equals(other: Commitment): boolean {
    return this.A.equals(other.A) && this.B.equals(other.B);
  }

  toJSON(): CommitmentJSON {
    return {
      A: this.A.toString(),
      B: this.B.toString(),
    };
  }
}
