import {
  assert,
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { CryptoSystem, KeyPair, Plaintext } from "../src/index.ts";
import { BigInteger } from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

// Valor fixo para testes determinísticos
const FIXED_PRIVATE_KEY = "12345678901234567890";

Deno.test("CryptoSystem::construtor", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);

  const cryptoSystem = new CryptoSystem(p, q, g);

  // Verifica se os valores foram atribuídos corretamente
  // Nota: Como os valores são privados, não conseguimos acessá-los diretamente
  // Podemos verificar através do method toJSON
  const json = cryptoSystem.toJSON();
  assertEquals(json.p, CRYPTO_PARAMS.p);
  assertEquals(json.q, CRYPTO_PARAMS.q);
  assertEquals(json.g, CRYPTO_PARAMS.g);
});

Deno.test("CryptoSystem::fromJSON", () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  assertEquals(cryptoSystem.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(cryptoSystem.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(cryptoSystem.g.toString(), CRYPTO_PARAMS.g);
});

Deno.test("CryptoSystem::generateSecureParams", async () => {
  const cryptoSystem = await CryptoSystem.generateSecureParams(512);

  assert(cryptoSystem.p instanceof BigInteger);
  assert(cryptoSystem.q instanceof BigInteger);
  assert(cryptoSystem.g instanceof BigInteger);

  // Gera um par de chaves
  const keyPair = await cryptoSystem.generateKeyPair();

  // Verifica a relação entre chave pública e privada
  const calculatedY = keyPair.pk.g.modPow(keyPair.sk.x, keyPair.pk.p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());

  await assertRejects(
    async () => {
      await CryptoSystem.generateSecureParams(510);
    },
    Error,
    "Tamanho de bits muito pequeno para segurança adequada",
  );
});

Deno.test("CryptoSystem::generateKeyPair", async () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  // Gera um par de chaves
  const keyPair = await cryptoSystem.generateKeyPair();

  // Verifica se o par de chaves foi gerado corretamente
  assertEquals(keyPair instanceof KeyPair, true);

  // Verifica se os parâmetros criptográficos no par de chaves correspondem ao sistema
  assertEquals(keyPair.pk.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(keyPair.pk.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(keyPair.pk.g.toString(), CRYPTO_PARAMS.g);

  // Verifica a relação entre chave pública e privada
  const calculatedY = keyPair.pk.g.modPow(keyPair.sk.x, keyPair.pk.p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());
});

Deno.test("CryptoSystem::generateKeyPairWithPrivateKey", () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  // Gera um par de chaves com chave privada específica
  const keyPair = cryptoSystem.generateKeyPairWithPrivateKey(FIXED_PRIVATE_KEY);

  // Verifica se a chave privada foi atribuída corretamente
  assertEquals(keyPair.sk.x.toString(), FIXED_PRIVATE_KEY);

  // Verifica se a chave pública foi calculada corretamente
  const expectedY = new BigInteger(CRYPTO_PARAMS.g)
    .modPow(new BigInteger(FIXED_PRIVATE_KEY), new BigInteger(CRYPTO_PARAMS.p));
  assertEquals(keyPair.pk.y.toString(), expectedY.toString());
});

Deno.test("CryptoSystem::toJSON", () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  // Converte para JSON
  const jsonOutput = cryptoSystem.toJSON();

  // Verifica a estrutura e os valores do JSON
  assertEquals(jsonOutput.p, CRYPTO_PARAMS.p);
  assertEquals(jsonOutput.q, CRYPTO_PARAMS.q);
  assertEquals(jsonOutput.g, CRYPTO_PARAMS.g);
});

Deno.test("CryptoSystem::ciclo completo de encriptação/decriptação", async () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);
  const keyPair = await cryptoSystem.generateKeyPair();

  // Mensagem a ser encriptada
  const message = "Mensagem secreta";
  const plaintext = await Plaintext.fromString(message);

  // Encripta a mensagem
  const ciphertext = await keyPair.pk.encrypt(plaintext);

  // Decripta a mensagem
  const decryptedPlaintext = keyPair.sk.decrypt(ciphertext);

  // Verifica se a mensagem decriptada corresponde à original
  assertEquals(await decryptedPlaintext.compareToString(message), true);
});

Deno.test("CryptoSystem::múltiplos pares de chaves independentes", async () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  // Gera múltiplos pares de chaves
  const [keyPair1, keyPair2, keyPair3] = await Promise.all([
    cryptoSystem.generateKeyPair(),
    cryptoSystem.generateKeyPair(),
    cryptoSystem.generateKeyPair(),
  ]);

  // Verifica se as chaves privadas são diferentes
  assertNotEquals(keyPair1.sk.x.toString(), keyPair2.sk.x.toString());
  assertNotEquals(keyPair1.sk.x.toString(), keyPair3.sk.x.toString());
  assertNotEquals(keyPair2.sk.x.toString(), keyPair3.sk.x.toString());

  // Verifica se as chaves públicas são diferentes
  assertNotEquals(keyPair1.pk.y.toString(), keyPair2.pk.y.toString());
  assertNotEquals(keyPair1.pk.y.toString(), keyPair3.pk.y.toString());
  assertNotEquals(keyPair2.pk.y.toString(), keyPair3.pk.y.toString());

  // Mas os parâmetros do sistema devem ser os mesmos
  assertEquals(keyPair1.pk.p.toString(), keyPair2.pk.p.toString());
  assertEquals(keyPair1.pk.q.toString(), keyPair2.pk.q.toString());
  assertEquals(keyPair1.pk.g.toString(), keyPair2.pk.g.toString());
});

Deno.test("CryptoSystem::compatibilidade entre chaves do mesmo sistema", async () => {
  const cryptoSystem = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  // Gera dois pares de chaves
  const [keyPair1, keyPair2] = await Promise.all([
    cryptoSystem.generateKeyPair(),
    cryptoSystem.generateKeyPair(),
  ]);

  // Mensagem a ser encriptada
  const message = "Mensagem secreta";
  const plaintext = await Plaintext.fromString(message);

  // Encripta com a primeira chave pública
  const ciphertext = await keyPair1.pk.encrypt(plaintext);

  // Mensagem encriptada com a primeira chave pública não pode ser decriptada com a segunda chave privada
  const wrongDecryption = keyPair2.sk.decrypt(ciphertext);
  assertNotEquals(await wrongDecryption.compareToString(message), true);

  // Mas pode ser decriptada com a primeira chave privada
  const correctDecryption = keyPair1.sk.decrypt(ciphertext);
  assertEquals(await correctDecryption.compareToString(message), true);
});
