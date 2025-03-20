import {
  assert,
  assertEquals,
  assertFalse,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { BigInteger, sha1ToBigInt } from "../src/utils/index.ts";
import { Plaintext } from "../src/index.ts";

Deno.test("Plaintext::fromString", async () => {
  const message = "Hello World";
  const plaintext = await Plaintext.fromString(message);

  // Verifica se a mensagem foi convertida corretamente para BigInteger
  const expectedHash = await sha1ToBigInt(message);
  assertEquals(plaintext.m.toString(), expectedHash.toString());
  assert(await plaintext.compareToString(message));
});

Deno.test("Plaintext::fromBigInteger", () => {
  const bigInt = new BigInteger("12345");
  const plaintext = Plaintext.fromBigInteger(bigInt);

  // Verifica se o BigInteger foi armazenado corretamente
  assertEquals(plaintext.m.toString(), "12345");

  // Verifica se o method fromBigInteger funciona corretamente
  const plaintextWithPK = Plaintext.fromBigInteger(bigInt);
  assertEquals(plaintextWithPK.m.toString(), "12345");
});

Deno.test("Plaintext::fromStrings", async () => {
  const messages = ["Hello", "World", "Test"];
  const nums = await Promise.all(messages.map((m) => sha1ToBigInt(m)));
  const plaintexts = await Plaintext.fromStrings(messages);

  // Verifica se todas as mensagens foram convertidas corretamente
  assertEquals(plaintexts.length, 3);
  assertEquals(plaintexts[0].m.toString(), nums[0].toString());
  assertEquals(plaintexts[1].m.toString(), nums[1].toString());
  assertEquals(plaintexts[2].m.toString(), nums[2].toString());
});

Deno.test("Plaintext::toString", () => {
  const bigInt = new BigInteger("12345");
  const plaintext = Plaintext.fromBigInteger(bigInt);

  // Verifica se o method toString retorna a representação correta do BigInteger
  assertEquals(plaintext.toString(), "12345");
});

Deno.test("Plaintext::valueOf", () => {
  const bigInt = new BigInteger("12345");
  const plaintext = Plaintext.fromBigInteger(bigInt);

  // Verifica se o method toString retorna a representação correta do BigInteger
  assert(bigInt.equals(plaintext.valueOf()));
});

Deno.test("Plaintext::compareToString", async () => {
  const message = "Hello World";
  const plaintext = await Plaintext.fromString(message);

  // Verifica se a comparação com a string original retorna verdadeiro
  assert(await plaintext.compareToString(message));

  // Verifica se a comparação com uma string diferente retorna falso
  assertFalse(await plaintext.compareToString("Different message"));
});

Deno.test("Plaintext::equals", async () => {
  const message = "Hello World";
  const plaintext = await Plaintext.fromString(message);

  // Verifica se a comparação com a string original retorna verdadeiro
  assert(await plaintext.compareToString(message));

  // Verifica se a comparação com uma string diferente retorna falso
  assertFalse(await plaintext.compareToString("Different message"));

  // Compara se é igual ao valor original
  const plaintext2 = await Plaintext.fromString(message);
  assert(plaintext.equals(plaintext2));

  // Compara se é diferente de outro valor
  const plaintext3 = await Plaintext.fromString("Different message");
  assertFalse(plaintext.equals(plaintext3));
});
