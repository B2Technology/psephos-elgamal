/**
 * BigInteger.ts
 *
 * A TypeScript implementation of the BigInteger library based on jsbn by Tom Wu
 * Refactored for Deno compatibility with TypeScript types
 * Uses native bigint type
 */

type NumberLike = number | string | bigint | null | undefined | BigInteger;

/**
 * BigInteger class for arbitrary-precision integer arithmetic
 */
export class BigInteger {
  private readonly num: bigint;

  /**
   * Constructor
   */
  constructor(num?: NumberLike) {
    if (num === null || num === undefined) {
      this.num = 0n;
    } else if (num instanceof BigInteger) {
      this.num = num.num;
    } else if (typeof num === "bigint") {
      this.num = num;
    } else if (typeof num === "number") {
      this.num = BigInt(num);
    } else if (typeof num === "string") {
      // Handle hex strings with 0x prefix
      if (num.toLowerCase().startsWith("0x")) {
        this.num = BigInt(num);
      } else {
        // Try to parse as decimal
        try {
          this.num = BigInt(num);
        } catch (_e) {
          throw new Error(`Cannot convert "${num}" to BigInteger`);
        }
      }
    } else {
      throw new Error(`Cannot convert ${typeof num} to BigInteger`);
    }
  }

  static readonly ZERO: BigInteger = new BigInteger(0);

  static readonly ONE: BigInteger = new BigInteger(1);

  /**
   * Converts a NumberLike value to bigint
   */
  private static toBigInt(value: NumberLike): bigint {
    if (value === null || value === undefined) {
      return 0n;
    } else if (value instanceof BigInteger) {
      return value.num;
    } else if (typeof value === "bigint") {
      return value;
    } else if (typeof value === "number") {
      return BigInt(value);
    } else if (typeof value === "string") {
      return BigInt(value);
    } else {
      throw new Error(`Cannot convert ${typeof value} to bigint`);
    }
  }

  /**
   * Calculates modular exponentiation (this^e mod m)
   * Implementation using right-to-left binary method (square and multiply)
   */
  public modPow(e: NumberLike, m: NumberLike): BigInteger {
    const exponent = BigInteger.toBigInt(e);
    const modulus = BigInteger.toBigInt(m);

    // Handle special cases
    if (modulus === 1n) return BigInteger.ZERO;
    if (exponent < 0n) {
      // For negative exponents, we need to find modular inverse first
      return this.modInverse(m).modPow(new BigInteger(exponent * -1n), m);
    }

    // Simple implementation using right-to-left binary method
    let base = this.num % modulus;
    let result = 1n;
    let exp = exponent;

    while (exp > 0n) {
      if (exp & 1n) {
        result = (result * base) % modulus;
      }
      base = (base * base) % modulus;
      exp = exp >> 1n; // Bitwise right shift
    }

    const finalResult = new BigInteger(result);

    // If the modulus is in the specific format 10^k + d where d is small,
    // jsbn might be returning a different representation of the result.
    // For testing and compatibility with jsbn, let's try to identify such cases:
    if (
      modulus.toString().startsWith("1") &&
      modulus.toString().slice(1, -1).split("").every((c) => c === "0")
    ) {
      // This is a number of form 10^k + d
      console.log(
        "Note: The modulus is of form 10^k + d. JSBN might return a different representation.",
      );

      // Output both our result and the last few digits which might match JSBN's output
      const resultStr = result.toString();
      console.log(`Full result: ${resultStr}`);
      console.log(`Last 4 digits: ${resultStr.slice(-4)}`);
    }

    return finalResult;
  }

  /**
   * Compares this BigInteger with another value for equality
   */
  public equals(other: NumberLike): boolean {
    return this.num === BigInteger.toBigInt(other);
  }

  /**
   * Adds another value to this BigInteger
   */
  public add(other: NumberLike): BigInteger {
    return new BigInteger(this.num + BigInteger.toBigInt(other));
  }

  /**
   * Subtracts another value from this BigInteger
   */
  public subtract(other: NumberLike): BigInteger {
    return new BigInteger(this.num - BigInteger.toBigInt(other));
  }

  /**
   * Divides this BigInteger by another value
   */
  public divide(other: NumberLike): BigInteger {
    return new BigInteger(this.num / BigInteger.toBigInt(other));
  }

  /**
   * Returns the bit length of this BigInteger
   */
  public bitLength(): number {
    return this.toString(2).length;
  }

  /**
   * Calculates the modular multiplicative inverse (1/this mod m)
   */
  public modInverse(m: NumberLike): BigInteger {
    const modulus = BigInteger.toBigInt(m);

    if (modulus <= 0n) {
      throw new Error("Modulus must be positive");
    }

    // Special case for modulus 1
    if (modulus === 1n) {
      return BigInteger.ZERO;
    }

    // Implementation of extended Euclidean algorithm
    let [old_r, r] = [this.num % modulus, modulus];
    let [old_s, s] = [1n, 0n];
    let [old_t, t] = [0n, 1n];

    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
      [old_t, t] = [t, old_t - quotient * t];
    }

    // Make sure gcd is 1 (numbers are coprime)
    if (old_r !== 1n) {
      throw new Error("No modular inverse exists");
    }

    // Make sure the result is positive
    if (old_s < 0n) {
      old_s += modulus;
    }

    return new BigInteger(old_s);
  }

  /**
   * Raises this BigInteger to the power of e
   */
  public pow(e: NumberLike): BigInteger {
    const exponent = BigInteger.toBigInt(e);

    if (exponent < 0n) {
      throw new Error("Negative exponents are not supported for pow()");
    }

    return new BigInteger(this.num ** exponent);
  }

  /**
   * Multiplies this BigInteger by another value
   */
  public multiply(other: NumberLike): BigInteger {
    return new BigInteger(this.num * BigInteger.toBigInt(other));
  }

  /**
   * Returns the negation of this BigInteger (-this)
   */
  public negate(): BigInteger {
    return new BigInteger(-this.num);
  }

  /**
   * Compares this BigInteger with another value
   * Returns:
   * -1 if this < other
   *  0 if this = other
   *  1 if this > other
   */
  public compareTo(other: NumberLike): -1 | 0 | 1 {
    const otherValue = BigInteger.toBigInt(other);

    if (this.num < otherValue) return -1;
    if (this.num > otherValue) return 1;
    return 0;
  }

  /**
   * Calculates this BigInteger modulo m
   */
  public mod(m: NumberLike): BigInteger {
    const modulus = BigInteger.toBigInt(m);

    if (modulus <= 0n) {
      throw new Error("Modulus must be positive");
    }

    // Ensure the result is always positive (consistent with mathematical definition)
    let result = this.num % modulus;
    if (result < 0n) {
      result += modulus;
    }

    return new BigInteger(result);
  }

  /**
   * Converts this BigInteger to a string with an optional radix
   */
  public toString(radix: number = 10): string {
    if (radix === 16) {
      return "0x" + this.num.toString(16);
    }
    return this.num.toString(radix);
  }

  /**
   * Converts this BigInteger to a number
   * Note: This may lose precision for very large values
   */
  public toNumber(): number {
    return Number(this.num);
  }

  /**
   * Returns the underlying bigint value
   */
  public valueOf(): bigint {
    return this.num;
  }
}
