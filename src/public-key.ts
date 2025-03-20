import type { Plaintext } from "./plaintext.ts";
import type { DLogProof } from "./d-log-proof.ts";
import { Ciphertext } from "./ciphertext.ts";
import {
  BigInteger,
  type DLogChallengeGeneratorFn,
  randomMpzLt,
  sha1Fingerprint,
} from "./utils/index.ts";

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

    return new Ciphertext(alpha, beta, this);
  }

  /**
   * Encrypt a plaintext and return the randomness just generated and used.
   */
  async encryptReturnR(
    plaintext: Plaintext,
  ): Promise<[Ciphertext, BigInteger]> {
    const r = await randomMpzLt(this.q);
    const ciphertext = this.encryptWithR(plaintext, r);
    return [ciphertext, r];
  }

  /**
   * Encrypt a plaintext, obscure the randomness.
   */
  async encrypt(plaintext: Plaintext): Promise<Ciphertext> {
    const c = await this.encryptReturnR(plaintext);
    return c[0];
  }

  multiply(other: PublicKey | number): PublicKey {
    if (typeof other === "number") {
      if ((other === 0 || other === 1)) {
        return this;
      }

      throw new Error("invalid parameter type");
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

  /**
   * verify the proof of knowledge of the secret key
   * g^response = commitment * y^challenge
   *
   * Finalidade: Verificar se alguém que afirma possuir a chave privada correspondente à chave pública
   * realmente a possui, sem que essa chave privada seja revelada.
   */
  async verifySkProof(
    dlogProof: DLogProof,
    challengeGenerator: DLogChallengeGeneratorFn,
  ): Promise<boolean> {
    const leftSide = this.g.modPow(dlogProof.response, this.p);
    const rightSide = dlogProof.commitment
      .multiply(this.y.modPow(dlogProof.challenge, this.p))
      .mod(this.p);
    const g = await challengeGenerator(dlogProof.commitment);
    const expectedChallenge = g.mod(this.q);

    return (
      leftSide.equals(rightSide) &&
      dlogProof.challenge.equals(expectedChallenge)
    );
  }

  equals(other: PublicKey): boolean {
    return (
      this.p.equals(other.p) &&
      this.q.equals(other.q) &&
      this.g.equals(other.g) &&
      this.y.equals(other.y)
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
   * Usa SHA1 para criar um hash dos componentes da chave
   * @returns Uma string formatada como XX:XX:XX:... contendo os primeiros 20 bytes do hash
   */
  fingerprint(): Promise<string> {
    // Concatena as strings dos componentes da chave pública
    const publicKeyString = this.p.toString() +
      this.q.toString() +
      this.g.toString() +
      this.y.toString();

    return sha1Fingerprint(publicKeyString);
  }
}
