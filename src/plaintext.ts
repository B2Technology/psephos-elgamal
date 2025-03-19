import type { BigInteger } from "./utils/index.ts";
import { sha1ToBigInt } from "./utils/index.ts";

export class Plaintext {
  constructor(
    public readonly m: BigInteger,
  ) {}

  static async fromString(m: string): Promise<Plaintext> {
    return new Plaintext(await sha1ToBigInt(m));
  }

  static fromBigInteger(m: BigInteger): Plaintext {
    return new Plaintext(m);
  }

  static fromStrings(list: string[]): Promise<Plaintext[]> {
    return Promise.all(
      list.map(async (m) => new Plaintext(await sha1ToBigInt(m))),
    );
  }

  toString(): string {
    return this.m.toString();
  }

  async compareToString(s: string): Promise<boolean> {
    const c = await sha1ToBigInt(s);
    return c.equals(this.m);
  }
}
