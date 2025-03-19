import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { CryptoSystem, Plaintext } from "../src/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

Deno.test("Elgamal::CryptoSystem fromJSON", async () => {
  const message = "Hello, World!";
  const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);
  const keyPair = await system.generateKeyPair();

  const plaintext = await Plaintext.fromString(message);
  const encrypted = await keyPair.pk.encrypt(plaintext);

  const decrypted = keyPair.sk.decrypt(encrypted);
  assertEquals(await decrypted.compareToString(message), true);
  assertEquals(plaintext.toString(), decrypted.toString());
});

Deno.test("Elgamal::CryptoSystem generateSecureParams", async () => {
  const message = "Hello, World #2!";
  const system = await CryptoSystem.generateSecureParams(512);
  const keyPair = await system.generateKeyPair();

  const plaintext = await Plaintext.fromString(message);
  const encrypted = await keyPair.pk.encrypt(plaintext);

  const decrypted = keyPair.sk.decrypt(encrypted);
  assertEquals(await decrypted.compareToString(message), true);
  assertEquals(plaintext.toString(), decrypted.toString());
});
