import type { SecretKeyJSON } from "./secret-key.ts";
import { SecretKey } from "./secret-key.ts";
import type { PublicKeyJSON } from "./public-key.ts";
import { PublicKey } from "./public-key.ts";
import { type BigInteger, randomMpzLt } from "./utils/index.ts";

export type KeyPairJSON = {
  pk: PublicKeyJSON;
  sk: SecretKeyJSON;
};

export class KeyPair {
  constructor(
    public readonly pk: PublicKey,
    public readonly sk: SecretKey,
  ) {}

  static async create(
    p: BigInteger,
    q: BigInteger,
    g: BigInteger,
  ): Promise<KeyPair> {
    const sk_x = await randomMpzLt(q);
    return KeyPair.createWithPrivateKey(p, q, g, sk_x);
  }

  static createWithPrivateKey(
    p: BigInteger,
    q: BigInteger,
    g: BigInteger,
    sk_x: BigInteger,
  ): KeyPair {
    const pk_y = g.modPow(sk_x, p);

    const publicKey = new PublicKey(p, q, g, pk_y);
    const secretKey = new SecretKey(sk_x, publicKey);

    return new KeyPair(publicKey, secretKey);
  }

  static fromJSON(data: KeyPairJSON): KeyPair {
    return new KeyPair(
      PublicKey.fromJSON(data.pk),
      SecretKey.fromJSON(data.sk),
    );
  }

  toJSON(): KeyPairJSON {
    return {
      pk: this.pk.toJSON(),
      sk: this.sk.toJSON(),
    };
  }
}
