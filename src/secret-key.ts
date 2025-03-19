import type { ChallengeGeneratorFn } from "./types.ts";
import type { PublicKeyJSON } from "./public-key.ts";
import type { Ciphertext } from "./ciphertext.ts";
import type { ZKProofJSON } from "./zk-proof.ts";
import { Plaintext } from "./plaintext.ts";
import { PublicKey } from "./public-key.ts";
import { DLogProof } from "./d-log-proof.ts";
import { ZKProof } from "./zk-proof.ts";
import {
  BigInteger,
  fiatshamirChallengeGenerator,
  randomMpzLt,
  sha1ToBigInt,
} from "./utils/index.ts";

export type SecretKeyJSON = {
  x: string;
  publicKey: PublicKeyJSON;
};

export class SecretKey {
  get pk(): PublicKey {
    return this.publicKey;
  }

  constructor(
    public readonly x: BigInteger,
    public readonly publicKey: PublicKey,
  ) {}

  // TODO testar
  static async createFromPublicKey(pk: PublicKey): Promise<SecretKey> {
    const x = await randomMpzLt(pk.q);
    return new SecretKey(x, pk);
  }

  static fromJSON(data: SecretKeyJSON): SecretKey {
    return new SecretKey(
      new BigInteger(data.x),
      PublicKey.fromJSON(data.publicKey),
    );
  }

  /**
   * provide the decryption factor, not yet inverted because of needed proof
   */
  decryptionFactor(ciphertext: Ciphertext): BigInteger {
    return ciphertext.alpha.modPow(this.x, this.pk.p);
  }

  // TODO add test (not covered)
  /**
   * challenge generator is almost certainly
   * EG_fiatshamir_challenge_generator
   */
  async decryptionFactorAndProof(
    ciphertext: Ciphertext,
    challengeGenerator: ChallengeGeneratorFn | null = null,
  ): Promise<[BigInteger, ZKProof]> {
    if (!challengeGenerator) {
      challengeGenerator = fiatshamirChallengeGenerator;
    }

    const decFactor = this.decryptionFactor(ciphertext);
    const proof = await ZKProof.generate(
      this.pk.g,
      ciphertext.alpha,
      this.x,
      this.pk.p,
      this.pk.q,
      challengeGenerator,
    );

    return [decFactor, proof];
  }

  /**
   * Decrypt a ciphertext. Optional parameter decides whether to encode the message into the proper subgroup.
   */
  decrypt(
    ciphertext: Ciphertext,
    decFactor: BigInteger | null = null,
    decodeM: boolean = false,
  ): Plaintext {
    if (!decFactor) {
      decFactor = this.decryptionFactor(ciphertext);
    }

    const m = decFactor
      .modInverse(this.pk.p)
      .multiply(ciphertext.beta)
      .mod(this.pk.p);

    if (decodeM) {
      // TODO add test (not covered)
      let y: BigInteger;
      if (m.compareTo(this.pk.q) < 0) {
        y = m;
      } else {
        y = m.negate().mod(this.pk.p);
      }

      return new Plaintext(y.subtract(BigInteger.ONE));
    }

    return new Plaintext(m);
  }

  // TODO add test (not covered)
  /**
   * given g, y, alpha, beta/(encoded m), prove equality of discrete log
   * with Chaum Pedersen, and that discrete log is x, the secret key.
   *
   * Prover sends a=g^w, b=alpha^w for random w
   * Challenge c = sha1(a,b) with and b in decimal form
   * Prover sends t = w + xc
   *
   * Verifier will check that g^t = a * y^c
   * and alpha^t = b * beta/m ^ c
   */
  async proveDecryption(
    ciphertext: Ciphertext,
  ): Promise<[BigInteger, ZKProofJSON]> {
    const m = ciphertext.alpha
      .modPow(this.x, this.pk.p)
      .modInverse(this.pk.p)
      .multiply(ciphertext.beta)
      .mod(this.pk.p);

    // const betaOverM = ciphertext.beta
    //   .multiply(m.modInverse(this.pk.p))
    //   .mod(this.pk.p);

    const w = await randomMpzLt(this.pk.q);
    const a = this.pk.g.modPow(w, this.pk.p);
    const b = ciphertext.alpha.modPow(w, this.pk.p);

    const c = await sha1ToBigInt(`${a},${b}`);
    const t = w.add(this.x.multiply(c)).mod(this.pk.q);

    const result: ZKProofJSON = {
      commitment: { A: a.toString(), B: b.toString() },
      challenge: c.toString(),
      response: t.toString(),
    };

    return [m, result];
  }

  // TODO add test (not covered)
  /**
   * Generate a PoK of the secret key
   * Prover generates w, a random integer modulo q, and computes commitment = g^w mod p.
   * Verifier provides challenge modulo q.
   * Prover computes response = w + x*challenge mod q, where x is the secret key.
   */
  async proveSk(
    challengeGenerator: (commitment: BigInteger) => BigInteger,
  ): Promise<DLogProof> {
    const w = await randomMpzLt(this.pk.q);
    const commitment = this.pk.g.modPow(w, this.pk.p);
    const challenge = challengeGenerator(commitment).mod(this.pk.q);
    const response = w.add(this.x.multiply(challenge)).mod(this.pk.q);

    return new DLogProof(commitment, challenge, response);
  }

  toJSON(): SecretKeyJSON {
    return {
      x: this.x.toString(),
      publicKey: this.publicKey.toJSON(),
    };
  }
}
