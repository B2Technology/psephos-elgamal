import { BigInteger } from "./utils/big-Integer.ts";
import { KeyPair } from "./key-par.ts";

export type CryptoSystemJSON = {
  p: string;
  q: string;
  g: string;
};

export class CryptoSystem {
  constructor(
    private readonly p: BigInteger,
    private readonly q: BigInteger,
    private readonly g: BigInteger,
  ) {}

  static fromJSON(data: CryptoSystemJSON): CryptoSystem {
    return new CryptoSystem(
      new BigInteger(data.p),
      new BigInteger(data.q),
      new BigInteger(data.g),
    );
  }

  generateKeyPair(y?: string | BigInteger): KeyPair {
    const _y = y ? new BigInteger(y.toString()) : undefined;
    return KeyPair.create(this.p, this.q, this.g, _y);
  }

  generateKeyPairWithPrivateKey(x: string | BigInteger) {
    const sk_x = new BigInteger(x.toString());
    return KeyPair.createWithPrivateKey(this.p, this.q, this.g, sk_x);
  }

  toJSON(): CryptoSystemJSON {
    return {
      p: this.p.toString(),
      q: this.q.toString(),
      g: this.g.toString(),
    };
  }
}

/**
 * class Cryptosystem(object):
 *     def __init__(self):
 *       self.p = None
 *       self.q = None
 *       self.g = None
 *
 *     def generate_keypair(self):
 *       """
 *       generates a keypair in the setting
 *       """
 *
 *       keypair = KeyPair()
 *       keypair.generate(self.p, self.q, self.g)
 *
 *       return keypair
 */
