import { BigInteger } from "./utils/big-Integer.ts";
import { randomMpzLt } from "./utils.ts";
import { Commitment } from "./commitment.ts";
import type { ChallengeGeneratorFn } from "./types.ts";

export type ZKProofJSON = {
  commitment: { A: string; B: string };
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

  // TODO add test (not covered)
  /**
   * generate a DDH tuple proof, where challenge generator is
   * almost certainly EG_fiatshamir_challenge_generator
   */
  static generate(
    littleG: BigInteger,
    littleH: BigInteger,
    x: BigInteger,
    p: BigInteger,
    q: BigInteger,
    challengeGenerator: ChallengeGeneratorFn,
  ): ZKProof {
    const w = randomMpzLt(q);

    // # compute A = little_g^w, B=little_h^w
    const c_A = littleG.modPow(w, p);
    const c_B = littleH.modPow(w, p);

    const commitment = new Commitment(c_A, c_B);
    const challenge = challengeGenerator(commitment);
    const response = w.add(x.multiply(challenge)).mod(q);

    return new ZKProof(commitment, challenge, response);
  }

  // TODO add test (not covered)
  /**
   * Verify a DH tuple proof
   */
  verify(
    littleG: BigInteger,
    littleH: BigInteger,
    bigG: BigInteger,
    bigH: BigInteger,
    p: BigInteger,
    q: BigInteger,
    challengeGenerator: ChallengeGeneratorFn | null = null,
  ): boolean {
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
      thirdCheck = this.challenge.equals(challengeGenerator(this.commitment));
    }

    return firstCheck && secondCheck && thirdCheck;
  }

  toJSON(): ZKProofJSON {
    return {
      commitment: this.commitment.toJSON(),
      challenge: this.challenge.toString(),
      response: this.response.toString(),
    };
  }
}
