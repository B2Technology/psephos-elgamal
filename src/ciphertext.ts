import type { FiatShamirChallengeGeneratorFn } from "./utils/index.ts";
import type { Plaintext } from "./plaintext.ts";
import type { PublicKeyJSON } from "./public-key.ts";
import { PublicKey } from "./public-key.ts";
import {
  BigInteger,
  type DisjunctiveChallengeGeneratorFn,
  randomMpzLt,
} from "./utils/index.ts";
import { ZKDisjunctiveProof } from "./zk-disjunctive-proof.ts";
import { Commitment } from "./commitment.ts";
import { ZKProof } from "./zk-proof.ts";

export type CiphertextJSON = {
  alpha: string;
  beta: string;
  pk: PublicKeyJSON;
};

export type CiphertextCommitmentJSON = {
  alpha: string;
  beta: string;
};

export class Ciphertext {
  get pk(): PublicKey {
    if (!this._pk) {
      throw new Error("Ciphertext: PublicKey is not defined");
    }

    return this._pk;
  }

  constructor(
    public readonly alpha: BigInteger,
    public readonly beta: BigInteger,
    public readonly _pk?: PublicKey,
  ) {}

  static fromJSON(json: CiphertextJSON): Ciphertext {
    return new Ciphertext(
      new BigInteger(json.alpha),
      new BigInteger(json.beta),
      json.pk ? PublicKey.fromJSON(json.pk) : undefined,
    );
  }

  static fromData(
    data: { alpha: string; beta: string },
    pk?: PublicKey,
  ): Ciphertext {
    return new Ciphertext(
      new BigInteger(data.alpha),
      new BigInteger(data.beta),
      pk,
    );
  }

  /**
   * expects: "${alpha},${beta}"
   */
  static fromString(str: string, pk?: PublicKey): Ciphertext {
    const [alpha, beta] = str.split(",").map((s) => new BigInteger(s));

    if (!alpha || !beta) {
      throw new Error(
        'Formato inválido para Ciphertext! Formato esperado: "${alpha},${beta}"',
      );
    }

    return new Ciphertext(alpha, beta, pk);
  }

  /**
   * Homomorphic Multiplication of ciphertexts.
   */
  multiply(other: Ciphertext | number): Ciphertext {
    if (typeof other === "number") {
      if ((other === 0 || other === 1)) {
        return this;
      }

      throw new Error("invalid parameter type");
    }

    if (this.pk !== other.pk) {
      console.info(this.pk);
      console.info(other.pk);
      throw new Error("Ciphertexts com chaves públicas diferentes");
    }

    return new Ciphertext(
      this.alpha.multiply(other.alpha).mod(this.pk.p),
      this.beta.multiply(other.beta).mod(this.pk.p),
      this.pk,
    );
  }

  /**
   * We would do this homomorphically, except
   * that's no good when we do plaintext encoding of 1.
   *
   * Finalidade: reencriptar um ciphertext com um novo valor de r
   */
  reencWithR(r: BigInteger): Ciphertext {
    const alpha = this.alpha
      .multiply(this.pk.g.modPow(r, this.pk.p))
      .mod(this.pk.p);

    const beta = this.beta
      .multiply(this.pk.y.modPow(r, this.pk.p))
      .mod(this.pk.p);

    return new Ciphertext(alpha, beta, this.pk);
  }

  /**
   * Reencryption with fresh randomness, which is returned.
   */
  async reencReturnR(): Promise<[Ciphertext, BigInteger]> {
    const r = await randomMpzLt(this.pk.q);
    const newCiphertext = this.reencWithR(r);
    return [newCiphertext, r];
  }

  /**
   * Reencryption with fresh randomness, which is kept obscured (unlikely to be useful.)
   */
  async reenc(): Promise<Ciphertext> {
    const c = await this.reencReturnR();
    return c[0];
  }

  /**
   * Check for ciphertext equality.
   */
  equals(other: Ciphertext | null): boolean {
    if (other === null) {
      return false;
    }

    return this.alpha.equals(other.alpha) && this.beta.equals(other.beta);
  }

  /**
   * Generate the disjunctive encryption proof of encryption
   */
  async generateEncryptionProof(
    randomness: BigInteger,
    challengeGenerator: FiatShamirChallengeGeneratorFn,
  ): Promise<ZKProof> {
    const w = await randomMpzLt(this.pk.q);

    // # compute A=g^w, B=y^w
    const c_A = this.pk.g.modPow(w, this.pk.p);
    const c_B = this.pk.y.modPow(w, this.pk.p);

    // # generate challenge
    const commitment = new Commitment(c_A, c_B);
    const challenge = await challengeGenerator(commitment);

    // # Compute response = w + randomness * challenge
    const response = w.add(randomness.multiply(challenge)).mod(this.pk.q);

    return new ZKProof(commitment, challenge, response);
  }

  async simulateEncryptionProof(
    plaintext: Plaintext,
    challenge: BigInteger | null = null,
  ): Promise<ZKProof> {
    if (!challenge) {
      challenge = await randomMpzLt(this.pk.q);
    }

    // # compute beta/plaintext, the completion of the DH tuple
    const betaOverPlaintext = this.beta
      .multiply(plaintext.m.modInverse(this.pk.p))
      .mod(this.pk.p);

    // # random response, does not even need to depend on the challenge
    const response = await randomMpzLt(this.pk.q);

    // # now we compute A and B
    const c_A = this.alpha
      .modPow(challenge, this.pk.p)
      .modInverse(this.pk.p)
      .multiply(this.pk.g.modPow(response, this.pk.p))
      .mod(this.pk.p);

    const c_B = betaOverPlaintext
      .modPow(challenge, this.pk.p)
      .modInverse(this.pk.p)
      .multiply(this.pk.y.modPow(response, this.pk.p))
      .mod(this.pk.p);

    const commitment = new Commitment(c_A, c_B);

    return new ZKProof(commitment, challenge, response);
  }

  async generateDisjunctiveEncryptionProof(
    plaintexts: Plaintext[],
    realIndex: number,
    randomness: BigInteger,
    challengeGenerator: DisjunctiveChallengeGeneratorFn,
  ): Promise<ZKDisjunctiveProof> {
    // #note how the interface is as such so that the result does not reveal which is the real proof.
    const proofs: ZKProof[] = new Array(plaintexts.length).fill(null);

    if (!plaintexts[realIndex]) {
      throw new Error("realIndex is invalid");
    }

    // # go through all plaintexts and simulate the ones that must be simulated.
    for (let i = 0; i < plaintexts.length; i++) {
      if (i !== realIndex) {
        proofs[i] = await this.simulateEncryptionProof(plaintexts[i]);
      }
    }

    // # the function that generates the challenge
    const realChallengeGenerator = async (
      commitment: Commitment,
    ): Promise<BigInteger> => {
      // # set up the partial real proof so we're ready to get the hash
      proofs[realIndex] = new ZKProof(
        commitment,
        BigInteger.ZERO,
        BigInteger.ZERO,
      );

      // # get the commitments in a list and generate the whole disjunctive challenge
      const commitments = proofs.map((p) => p.commitment);
      const disjunctiveChallenge = await challengeGenerator(commitments);

      // # now we must subtract all of the other challenges from this challenge.
      let realChallenge = disjunctiveChallenge;
      for (let i = 0; i < proofs.length; i++) {
        if (i !== realIndex) {
          realChallenge = realChallenge.subtract(proofs[i].challenge);
        }
      }

      // # make sure we mod q, the exponent modulus
      return Promise.resolve(realChallenge.mod(this.pk.q));
    };

    // # do the real proof
    const realProof = await this.generateEncryptionProof(
      randomness,
      realChallengeGenerator,
    );

    // # set the real proof
    proofs[realIndex] = realProof;

    return new ZKDisjunctiveProof(proofs);
  }

  /**
   * Checks for the DDH tuple g, y, alpha, beta/plaintext.
   * (PoK of randomness r.)
   *
   * Proof contains commitment = {A, B}, challenge, response
   */
  verifyEncryptionProof(plaintext: Plaintext, proof: ZKProof): boolean {
    // # check that g^response = A * alpha^challenge
    const firstCheck = this.pk.g
      .modPow(proof.response, this.pk.p)
      .equals(
        this.alpha
          .modPow(proof.challenge, this.pk.p)
          .multiply(proof.commitment["A"])
          .mod(this.pk.p),
      );

    // # check that y^response = B * (beta/m)^challenge
    const betaOverM = this.beta
      .multiply(plaintext.m.modInverse(this.pk.p))
      .mod(this.pk.p);

    const secondCheck = this.pk.y
      .modPow(proof.response, this.pk.p)
      .equals(
        betaOverM
          .modPow(proof.challenge, this.pk.p)
          .multiply(proof.commitment["B"])
          .mod(this.pk.p),
      );

    return firstCheck && secondCheck;
  }

  /**
   * plaintexts and proofs are all lists of equal length, with matching.
   *
   * overall_challenge is what all of the challenges combined should yield.
   */
  async verifyDisjunctiveEncryptionProof(
    plaintexts: Plaintext[],
    proof: ZKDisjunctiveProof,
    challengeGenerator: DisjunctiveChallengeGeneratorFn,
  ): Promise<boolean> {
    if (plaintexts.length !== proof.proofs.length) {
      console.error(
        `bad number of proofs (expected ${plaintexts.length}, found ${proof.proofs.length})`,
      );
      return false;
    }

    for (let i = 0; i < plaintexts.length; i++) {
      // # if a proof fails, stop right there
      if (!this.verifyEncryptionProof(plaintexts[i], proof.proofs[i])) {
        console.error(
          `[${i}] bad proof: plaintexts ${plaintexts[i]} / ${
            JSON.stringify(proof.proofs[i])
          }`,
        );
        return false;
      }
    }

    // # logging.info("made it past the two encryption proofs")
    // # check the overall challenge
    const overallChallenge = await challengeGenerator(
      proof.proofs.map((p) => p.commitment),
    );

    const sumChallenges = proof.proofs
      .reduce((sum, p) => sum.add(p.challenge), BigInteger.ZERO)
      .mod(this.pk.q);

    return overallChallenge.equals(sumChallenges);
  }

  /**
   * decrypt a ciphertext given a list of decryption factors (from multiple trustees)
   * For now, no support for threshold
   */
  decrypt(decryptionFactors: BigInteger[], publicKey: PublicKey): BigInteger {
    let runningDecryption = this.beta;
    for (const decFactor of decryptionFactors) {
      runningDecryption = runningDecryption
        .multiply(decFactor.modInverse(publicKey.p))
        .mod(publicKey.p);
    }

    return runningDecryption;
  }

  toString(): string {
    return `${this.alpha},${this.beta}`;
  }

  toJSON(): CiphertextJSON {
    return {
      alpha: this.alpha.toString(),
      beta: this.beta.toString(),
      pk: this.pk.toJSON(),
    };
  }

  toCommitmentJSON(): CiphertextCommitmentJSON {
    return {
      alpha: this.alpha.toString(),
      beta: this.beta.toString(),
    };
  }
}
