import type { BigInteger } from "./utils/index.ts";
import { sha1ToBigInt } from "./utils/index.ts";

export class Plaintext {
  constructor(
    public readonly m: BigInteger,
  ) {}

  static fromString(m: string): Plaintext {
    return new Plaintext(sha1ToBigInt(m));
  }

  static fromBigInteger(m: BigInteger): Plaintext {
    return new Plaintext(m);
  }

  static fromStrings(list: string[]): Plaintext[] {
    return list.map((m) => new Plaintext(sha1ToBigInt(m)));
  }

  toString(): string {
    return this.m.toString();
  }

  compareToString(s: string): boolean {
    return sha1ToBigInt(s).equals(this.m);
  }
}
