import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { BigInteger } from "../../src/utils/big-Integer.ts";

// Helper function to compare BigInteger results with native bigint
function assertBigIntegerEquals(
  actual: BigInteger,
  expected: bigint | number | string,
): void {
  const expectedBigInt = typeof expected === "bigint"
    ? expected
    : BigInt(expected);

  assertEquals(actual.valueOf(), expectedBigInt);
}

Deno.test("BigInteger constructor", () => {
  // Test different input types
  assertBigIntegerEquals(new BigInteger(123), 123n);
  assertBigIntegerEquals(new BigInteger("456"), 456n);
  assertBigIntegerEquals(new BigInteger(789n), 789n);
  assertBigIntegerEquals(new BigInteger(new BigInteger(101112)), 101112n);

  // Test hex strings
  assertBigIntegerEquals(new BigInteger("0xff"), 255n);
  assertBigIntegerEquals(new BigInteger("0xDEADBEEF"), 0xDEADBEEFn);

  // Test null/undefined
  assertBigIntegerEquals(new BigInteger(null), 0n);
  assertBigIntegerEquals(new BigInteger(undefined), 0n);

  // Test static constants
  assertBigIntegerEquals(BigInteger.ZERO, 0n);
  assertBigIntegerEquals(BigInteger.ONE, 1n);
});

Deno.test("BigInteger addition", () => {
  const a = new BigInteger(12345);
  const b = new BigInteger(67890);

  // Test add method
  assertBigIntegerEquals(a.add(b), 12345n + 67890n);
  assertBigIntegerEquals(a.add(67890), 12345n + 67890n);
  assertBigIntegerEquals(a.add("67890"), 12345n + 67890n);
  assertBigIntegerEquals(a.add(67890n), 12345n + 67890n);

  // Test with large numbers
  const large1 = new BigInteger("9007199254740991"); // Max safe integer in JS
  const large2 = new BigInteger("9007199254740991");
  assertBigIntegerEquals(large1.add(large2), 18014398509481982n);
});

Deno.test("BigInteger subtraction", () => {
  const a = new BigInteger(67890);
  const b = new BigInteger(12345);

  // Test subtract method
  assertBigIntegerEquals(a.subtract(b), 67890n - 12345n);
  assertBigIntegerEquals(a.subtract(12345), 67890n - 12345n);
  assertBigIntegerEquals(a.subtract("12345"), 67890n - 12345n);
  assertBigIntegerEquals(a.subtract(12345n), 67890n - 12345n);

  // Test with negative result
  assertBigIntegerEquals(b.subtract(a), 12345n - 67890n);
});

Deno.test("BigInteger multiplication", () => {
  const a = new BigInteger(111);
  const b = new BigInteger(222);

  // Test multiply method
  assertBigIntegerEquals(a.multiply(b), 111n * 222n);
  assertBigIntegerEquals(a.multiply(222), 111n * 222n);
  assertBigIntegerEquals(a.multiply("222"), 111n * 222n);
  assertBigIntegerEquals(a.multiply(222n), 111n * 222n);

  // Test with large numbers
  const large1 = new BigInteger("9007199254740991"); // Max safe integer in JS
  const large2 = new BigInteger("9007199254740991");
  assertBigIntegerEquals(
    large1.multiply(large2),
    81129638414606663681390495662081n,
  );
});

Deno.test("BigInteger power", () => {
  const a = new BigInteger(2);

  // Test pow method
  assertBigIntegerEquals(a.pow(10), 1024n);
  assertBigIntegerEquals(a.pow("10"), 1024n);
  assertBigIntegerEquals(a.pow(10n), 1024n);
  assertBigIntegerEquals(a.pow(new BigInteger(10)), 1024n);

  // Test large exponent
  assertBigIntegerEquals(a.pow(64), 18446744073709551616n);

  // Test error with negative exponent
  assertThrows(() => a.pow(-1), Error, "Negative exponents are not supported");
});

Deno.test("BigInteger modulo", () => {
  const a = new BigInteger(100);
  const b = new BigInteger(30);

  // Test mod method
  assertBigIntegerEquals(a.mod(b), 10n);
  assertBigIntegerEquals(a.mod(30), 10n);
  assertBigIntegerEquals(a.mod("30"), 10n);
  assertBigIntegerEquals(a.mod(30n), 10n);

  // Test with negative number (should return positive modulo)
  const negative = new BigInteger(-100);
  assertBigIntegerEquals(negative.mod(30), 20n); // -100 mod 30 = 20 (positive result)

  // Test error with non-positive modulus
  assertThrows(() => a.mod(0), Error, "Modulus must be positive");
  assertThrows(() => a.mod(-30), Error, "Modulus must be positive");
});

Deno.test("BigInteger modular exponentiation", () => {
  // Base cases
  assertBigIntegerEquals(new BigInteger(4).modPow(13, 497), 445n);

  // Test all parameter types
  const base = new BigInteger(4);
  assertBigIntegerEquals(base.modPow(13, 497), 445n);
  assertBigIntegerEquals(base.modPow("13", 497), 445n);
  assertBigIntegerEquals(base.modPow(13n, 497), 445n);
  assertBigIntegerEquals(base.modPow(new BigInteger(13), 497), 445n);

  // Test larger values
  const a = new BigInteger(
    "2988348162058574136915891421498819466320163312926952423791023078876139",
  );
  const b = new BigInteger(
    "2351399303373464486466122544523690094744975233415544072992656881240319",
  );
  const c = new BigInteger("1527229998585248450016808958343740453059");
  const r = a.modPow(b, c);
  assertBigIntegerEquals(r, "1470102596195405640138667289299056235142");

  // Special case: modulus = 1
  assertBigIntegerEquals(base.modPow(13, 1), 0n);
});

Deno.test("BigInteger modular inverse", () => {
  // Simple test cases
  assertBigIntegerEquals(new BigInteger(3).modInverse(11), 4n);
  assertBigIntegerEquals(new BigInteger(10).modInverse(17), 12n);

  // Test all parameter types
  const a = new BigInteger(3);
  assertBigIntegerEquals(a.modInverse(11), 4n);
  assertBigIntegerEquals(a.modInverse("11"), 4n);
  assertBigIntegerEquals(a.modInverse(11n), 4n);
  assertBigIntegerEquals(a.modInverse(new BigInteger(11)), 4n);

  // Test larger values
  assertBigIntegerEquals(
    new BigInteger(123456791).modInverse(987654319),
    438957476n, // Valor correto verificado
  );

  // Test larger values #2
  const num = new BigInteger(123456791);
  const mod = new BigInteger(987654319);
  const inverse = num.modInverse(mod);

  // Verify that (num * inverse) mod modulus = 1
  assertBigIntegerEquals(
    num.multiply(inverse).mod(mod),
    1n,
  );

  // Test exceptions
  assertThrows(
    () => new BigInteger(4).modInverse(10),
    Error,
    "No modular inverse exists",
  );
  assertThrows(
    () => new BigInteger(6).modInverse(0),
    Error,
    "Modulus must be positive",
  );
  assertThrows(
    () => new BigInteger(6).modInverse(-5),
    Error,
    "Modulus must be positive",
  );
});

Deno.test("BigInteger equals", () => {
  const a = new BigInteger(12345);

  // Test equals with various types
  assertEquals(a.equals(12345), true);
  assertEquals(a.equals("12345"), true);
  assertEquals(a.equals(12345n), true);
  assertEquals(a.equals(new BigInteger(12345)), true);

  // Test not equals
  assertEquals(a.equals(54321), false);
  assertEquals(a.equals("54321"), false);
  assertEquals(a.equals(54321n), false);
  assertEquals(a.equals(new BigInteger(54321)), false);
});

Deno.test("BigInteger toString", () => {
  const a = new BigInteger(12345);

  // Default base 10
  assertEquals(a.toString(), "12345");

  // Hexadecimal
  assertEquals(a.toString(16), "0x3039");

  // Binary
  assertEquals(a.toString(2), "11000000111001");

  // Large number
  const large = new BigInteger("340282366920938463463374607431768211456");
  assertEquals(large.toString(), "340282366920938463463374607431768211456");
});

Deno.test("BigInteger toNumber", () => {
  // Small number
  const small = new BigInteger(12345);
  assertEquals(small.toNumber(), 12345);

  // Max safe integer
  const maxSafe = new BigInteger(Number.MAX_SAFE_INTEGER);
  assertEquals(maxSafe.toNumber(), Number.MAX_SAFE_INTEGER);

  // Note: larger values might lose precision when converted to number
});

Deno.test("BigInteger compareTo", () => {
  const a = new BigInteger(42);
  const b = new BigInteger(100);
  const c = new BigInteger(42);

  assertEquals(a.compareTo(b), -1); // -1 (42 < 100)
  assertEquals(b.compareTo(a), 1); // 1 (100 > 42)
  assertEquals(a.compareTo(c), 0); // 0 (42 = 42)

  // Também funciona com outros tipos
  assertEquals(a.compareTo(42), 0); // 0
  assertEquals(a.compareTo("100"), -1); // -1
  assertEquals(b.compareTo(42n), 1); // 1
});

Deno.test("BigInteger negate", () => {
  // Criando um BigInteger
  const positivo = new BigInteger(42);
  assertEquals(positivo.toString(), "42");

  // Aplicando o método negate()
  const negativo = positivo.negate();
  assertEquals(negativo.toString(), "-42");
  assertEquals(negativo.toNumber(), -42);

  // Também funciona com números já negativos
  const jaNegativo = new BigInteger(-100);
  const positivoAgain = jaNegativo.negate();
  assertEquals(positivoAgain.toString(), "100");
  assertEquals(positivoAgain.toNumber(), 100);
});
