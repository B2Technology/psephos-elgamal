import type { CommitmentJSON } from "./commitment.ts";
import { Commitment } from "./commitment.ts";
import {
  BigInteger,
  type FiatShamirChallengeGeneratorFn,
  randomMpzLt,
} from "./utils/index.ts";

export type ZKProofJSON = {
  commitment: CommitmentJSON;
  challenge: string;
  response: string;
};

export class ZKProof {
  constructor(
    public readonly commitment: Commitment,
    public readonly challenge: BigInteger,
    public readonly response: BigInteger,
  ) {}

  static fromJSON(data: ZKProofJSON): ZKProof {
    return new ZKProof(
      Commitment.fromJSON(data.commitment),
      new BigInteger(data.challenge),
      new BigInteger(data.response),
    );
  }

  /**
   * generate a DDH tuple proof, where challenge generator is
   * almost certainly EG_fiatshamir_challenge_generator
   */
  static async generate(
    littleG: BigInteger,
    littleH: BigInteger,
    x: BigInteger,
    p: BigInteger,
    q: BigInteger,
    challengeGenerator: FiatShamirChallengeGeneratorFn,
  ): Promise<ZKProof> {
    const w = await randomMpzLt(q);

    // # compute A = little_g^w, B=little_h^w
    const c_A = littleG.modPow(w, p);
    const c_B = littleH.modPow(w, p);

    const commitment = new Commitment(c_A, c_B);
    const challenge = await challengeGenerator(commitment);
    const response = w.add(x.multiply(challenge)).mod(q);

    return new ZKProof(commitment, challenge, response);
  }

  /**
   * Verify a DH tuple proof
   */
  async verify(
    littleG: BigInteger,
    littleH: BigInteger,
    bigG: BigInteger,
    bigH: BigInteger,
    p: BigInteger,
    _q: BigInteger,
    challengeGenerator: FiatShamirChallengeGeneratorFn | null = null,
  ): Promise<boolean> {
    // # check that little_g^response = A * big_g^challenge
    const firstCheck = littleG
      .modPow(this.response, p)
      .equals(
        bigG.modPow(this.challenge, p).multiply(this.commitment.A).mod(p),
      );

    // # check that little_h^response = B * big_h^challenge
    const secondCheck = littleH
      .modPow(this.response, p)
      .equals(
        bigH.modPow(this.challenge, p).multiply(this.commitment.B).mod(p),
      );

    // # check the challenge?
    let thirdCheck = true;
    if (challengeGenerator) {
      thirdCheck = this.challenge.equals(
        await challengeGenerator(this.commitment),
      );
    }

    return firstCheck && secondCheck && thirdCheck;
  }

  equals(other: ZKProof): boolean {
    return (
      this.commitment.equals(other.commitment) &&
      this.challenge.equals(other.challenge) &&
      this.response.equals(other.response)
    );
  }

  toJSON(): ZKProofJSON {
    return {
      commitment: this.commitment.toJSON(),
      challenge: this.challenge.toString(),
      response: this.response.toString(),
    };
  }
}
