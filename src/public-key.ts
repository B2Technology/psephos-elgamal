import crypto from "node:crypto";
import { BigInteger } from "./utils/big-Integer.ts";
import { Ciphertext } from "./ciphertext.ts";
import { fiatshamirChallengeGenerator, randomMpzLt } from "./utils.ts";
import type { Plaintext } from "./plaintext.ts";
import type { DLogProof } from "./d-log-proof.ts";
import type { ZKProof } from "./zk-proof.ts";

export type PublicKeyJSON = {
  p: string;
  q: string;
  g: string;
  y: string;
};

/**
 * Todas as public keys compartilham o mesmo $p, $q e $g (originado do CryptoSystem)
 *
 * Cada public key tem um $y diferente BingInt
 */

export class PublicKey {
  constructor(
    public readonly p: BigInteger,
    public readonly q: BigInteger,
    public readonly g: BigInteger,
    public readonly y: BigInteger,
  ) {}

  static fromJSON(data: PublicKeyJSON): PublicKey {
    return new PublicKey(
      new BigInteger(data.p),
      new BigInteger(data.q),
      new BigInteger(data.g),
      new BigInteger(data.y),
    );
  }

  /**
   *  Expecting plaintext.m to be a big integer
   */
  encryptWithR(
    plaintext: Plaintext,
    r: BigInteger,
    encodeMessage: boolean = false,
  ): Ciphertext {
    let m: BigInteger;

    if (encodeMessage) {
      // TODO add test (not covered)
      const y = plaintext.m.add(BigInteger.ONE);
      if (y.modPow(this.q, this.p).equals(BigInteger.ONE)) {
        m = y;
      } else {
        m = y.negate().mod(this.p);
      }
    } else {
      m = plaintext.m;
    }

    const alpha = this.g.modPow(r, this.p);
    const beta = this.y.modPow(r, this.p).multiply(m).mod(this.p);
    // const beta = m.multiply(this.y.modPow(r, this.p)).mod(this.p);// TODO remove

    return new Ciphertext(alpha, beta, this);
  }

  /**
   * Encrypt a plaintext and return the randomness just generated and used.
   */
  encryptReturnR(plaintext: Plaintext): [Ciphertext, BigInteger] {
    const r = randomMpzLt(this.q);
    const ciphertext = this.encryptWithR(plaintext, r);
    return [ciphertext, r];
  }

  /**
   * Encrypt a plaintext, obscure the randomness.
   */
  encrypt(plaintext: Plaintext): Ciphertext {
    return this.encryptReturnR(plaintext)[0];
  }

  /**
   * Encrypt a plaintext, obscure the randomness and generate a proof of knowledge of the randomness
   */
  generateProof(plaintext: Plaintext): ZKProof {
    const [ciphertext, r] = this.encryptReturnR(plaintext);

    return ciphertext.generateEncryptionProof(
      plaintext,
      r,
      fiatshamirChallengeGenerator,
    );
  }

  // verifyProof(plaintext: Plaintext, encryptProof: ZKProof): boolean {
  //   const { A, B } = encryptProof.commitment;
  //
  //   return new Ciphertext(A, B, this).verifyEncryptionProof(
  //     plaintext,
  //     encryptProof,
  //   );
  // }

  // TODO add test (not covered)
  multiply(other: PublicKey): PublicKey {
    if (typeof other === "number" && (other === 0 || other === 1)) {
      return this;
    }

    if (
      !this.p.equals(other.p) ||
      !this.q.equals(other.q) ||
      !this.g.equals(other.g)
    ) {
      throw new Error("incompatible public keys");
    }

    return new PublicKey(
      this.p,
      this.q,
      this.g,
      this.y.multiply(other.y).mod(this.p),
    );
  }

  // TODO add test (not covered)
  /**
   * verify the proof of knowledge of the secret key
   * g^response = commitment * y^challenge
   */
  verifySkProof(
    dlogProof: DLogProof,
    challengeGenerator: (commitment: BigInteger) => BigInteger,
  ): boolean {
    const leftSide = this.g.modPow(dlogProof.response, this.p);
    const rightSide = dlogProof.commitment
      .multiply(this.y.modPow(dlogProof.challenge, this.p))
      .mod(this.p);
    const expectedChallenge = challengeGenerator(dlogProof.commitment).mod(
      this.q,
    );

    return (
      leftSide.equals(rightSide) &&
      dlogProof.challenge.equals(expectedChallenge)
    );
  }

  toJSON(): PublicKeyJSON {
    return {
      p: this.p.toString(),
      q: this.q.toString(),
      g: this.g.toString(),
      y: this.y.toString(),
    };
  }

  /**
   * Gera um fingerprint único para identificar esta chave pública
   * Usa SHA-256 para criar um hash dos componentes da chave
   * @returns Uma string formatada como XX:XX:XX:... contendo os primeiros 20 bytes do hash
   */
  fingerprint(): string {
    // Concatena as strings dos componentes da chave pública
    const publicKeyString = this.p.toString() +
      this.q.toString() +
      this.g.toString() +
      this.y.toString();

    // Calcula o hash SHA-256 da string
    const hash = crypto
      .createHash("sha256")
      .update(publicKeyString, "utf-8")
      .digest();

    // Converte para formato de fingerprint (primeiros 20 bytes em formato hexadecimal com separadores)
    const fingerprintBytes = hash.slice(0, 20);
    const fingerprint = Array.from(fingerprintBytes)
      .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
      .join(":");

    return fingerprint;
  }
}
