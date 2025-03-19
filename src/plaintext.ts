import { BigInteger } from "./utils/big-Integer.ts";
import { PublicKey } from "./public-key.ts";
import { sha1ToBigInt } from "./utils.ts";

export class Plaintext {
  // public readonly pk: PublicKey | null
  constructor(
    public readonly m: BigInteger,
    pk: PublicKey | null, // TODO remove
  ) {}

  static fromString(m: string, pk?: PublicKey): Plaintext {
    return new Plaintext(sha1ToBigInt(m), pk || null);
  }

  static fromBigInteger(m: BigInteger, pk?: PublicKey): Plaintext {
    return new Plaintext(m, pk || null);
  }

  static fromStrings(list: string[], pk?: PublicKey): Plaintext[] {
    return list.map((m) => new Plaintext(sha1ToBigInt(m), pk || null));
  }

  toString(): string {
    return this.m.toString();
  }

  compareToString(s: string): boolean {
    return sha1ToBigInt(s).equals(this.m);
  }
}
