import {
  assert,
  assertEquals,
  assertFalse,
  assertNotEquals,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { CryptoSystem, KeyPair, PublicKey, SecretKey } from "../src/index.ts";
import { BigInteger } from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

// Valor fixo para testes determinísticos
const FIXED_PRIVATE_KEY = "12345678901234567890";
const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

Deno.test("KeyPair::construtor", async () => {
  const keyPair = await system.generateKeyPair();

  // Verifica se o par de chaves foi criado corretamente
  assertEquals(keyPair.pk instanceof PublicKey, true);
  assertEquals(keyPair.sk instanceof SecretKey, true);

  // Verifica se a chave privada está corretamente relacionada à chave pública
  assertEquals(keyPair.pk.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(keyPair.pk.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(keyPair.pk.g.toString(), CRYPTO_PARAMS.g);

  // Verifica se a chave pública na chave privada é a mesma instância
  assertEquals(keyPair.sk.pk, keyPair.pk);
});

Deno.test("KeyPair::create", async () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);

  // Cria um par de chaves usando o method estático create
  const keyPair = await KeyPair.create(p, q, g);

  // Verifica se o par de chaves foi criado corretamente
  assertEquals(keyPair.pk instanceof PublicKey, true);
  assertEquals(keyPair.sk instanceof SecretKey, true);

  // Verifica se os parâmetros foram corretamente atribuídos
  assertEquals(keyPair.pk.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(keyPair.pk.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(keyPair.pk.g.toString(), CRYPTO_PARAMS.g);

  // Verifica a relação entre as chaves: g^x mod p = y
  const calculatedY = g.modPow(keyPair.sk.x, p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());

  // Deve gerar pares de chaves diferentes
  const keyPair2 = await KeyPair.create(p, q, g);
  assertFalse(keyPair.sk.equals(keyPair2.sk));
  assertFalse(keyPair.pk.equals(keyPair2.pk));
});

Deno.test("KeyPair::createWithPrivateKey", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);
  const sk_x = new BigInteger(FIXED_PRIVATE_KEY);

  // Cria um par de chaves com uma chave privada específica
  const keyPair = KeyPair.createWithPrivateKey(p, q, g, sk_x);

  // Verifica se a chave privada é a especificada
  assertEquals(keyPair.sk.x.toString(), FIXED_PRIVATE_KEY);

  // Verifica a relação entre as chaves: g^x mod p = y
  const calculatedY = g.modPow(sk_x, p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());
});

Deno.test("KeyPair::fromJSON e toJSON", async () => {
  const originalKeyPair = await system.generateKeyPair();

  // Converte para JSON
  const jsonData = originalKeyPair.toJSON();

  // Verifica estrutura JSON
  assertEquals(typeof jsonData.pk, "object");
  assertEquals(typeof jsonData.sk, "object");
  assertEquals(typeof jsonData.pk.p, "string");
  assertEquals(typeof jsonData.pk.q, "string");
  assertEquals(typeof jsonData.pk.g, "string");
  assertEquals(typeof jsonData.pk.y, "string");
  assertEquals(typeof jsonData.sk.x, "string");
  assertEquals(typeof jsonData.sk.publicKey, "object");

  // Recria a partir do JSON
  const recreatedKeyPair = KeyPair.fromJSON(jsonData);

  // Verifica se as chaves foram recriadas corretamente
  assert(
    originalKeyPair.pk.equals(recreatedKeyPair.pk),
  );
  assert(
    originalKeyPair.sk.equals(recreatedKeyPair.sk),
  );
});

Deno.test("KeyPair::pares de chaves diferentes devem ter chaves privadas diferentes", async () => {
  const [keyPair1, keyPair2] = await Promise.all([
    system.generateKeyPair(),
    system.generateKeyPair(),
  ]);

  // Valores de p, q e g devem ser iguais
  assertEquals(keyPair1.pk.p.toString(), keyPair2.pk.p.toString());
  assertEquals(keyPair1.pk.q.toString(), keyPair2.pk.q.toString());
  assertEquals(keyPair1.pk.g.toString(), keyPair2.pk.g.toString());

  // Chaves privadas devem ser diferentes
  assertNotEquals(keyPair1.sk.x.toString(), keyPair2.sk.x.toString());

  // Chaves públicas também devem ser diferentes
  assertNotEquals(keyPair1.pk.y.toString(), keyPair2.pk.y.toString());
});

Deno.test("KeyPair::mesma chave privada deve gerar mesma chave pública", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);
  const sk_x = new BigInteger(FIXED_PRIVATE_KEY);

  // Cria dois pares de chaves com a mesma chave privada
  const keyPair1 = KeyPair.createWithPrivateKey(p, q, g, sk_x);
  const keyPair2 = KeyPair.createWithPrivateKey(p, q, g, sk_x);

  // As chaves públicas devem ser iguais
  assert(keyPair1.pk.equals(keyPair2.pk));
  assert(keyPair1.sk.equals(keyPair2.sk));
});
