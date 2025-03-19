import {
  assert,
  assertEquals,
  assertFalse,
  assertNotEquals,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import {
  CryptoSystem,
  DLogProof,
  Plaintext,
  SecretKey,
  type SecretKeyJSON,
} from "../src/index.ts";
import { BigInteger, dLogChallengeGenerator } from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

Deno.test("SecretKey::construtor", async () => {
  const x = new BigInteger("12345678901234567890");
  const keyPair = await system.generateKeyPair();
  const secretKey = new SecretKey(x, keyPair.pk);

  // Verifica se os valores foram atribuídos corretamente
  assertEquals(secretKey.x.toString(), "12345678901234567890");
  assert(secretKey.x.equals(x));
  assert(secretKey.publicKey.equals(keyPair.pk));
  assert(secretKey.publicKey.equals(secretKey.pk)); // test getter pk

  // Verifica se o getter pk retorna a publicKey
  assert(secretKey.pk.equals(keyPair.pk));
});

Deno.test("SecretKey::createFromPublicKey", async () => {
  const keyPair = await system.generateKeyPair();

  // Cria uma nova SecretKey a partir de uma PublicKey existente
  const secretKey = await SecretKey.createFromPublicKey(keyPair.pk);

  // Verifica se a chave secreta foi criada
  assertEquals(secretKey instanceof SecretKey, true);
  assertEquals(secretKey.x instanceof BigInteger, true);
  assert(secretKey.publicKey.equals(keyPair.pk));

  // A chave gerada deve ter um valor x diferente da original
  assertNotEquals(secretKey.x.toString(), keyPair.sk.x.toString());

  // Se gerar uma nova chave a partir da mesma PublicKey, deve ser diferente
  const secretKey2 = await SecretKey.createFromPublicKey(keyPair.pk);
  assertFalse(secretKey.equals(secretKey2));
  assertFalse(secretKey.x.equals(secretKey2.x));
});

Deno.test("SecretKey::fromJSON", () => {
  const jsonData: SecretKeyJSON = {
    x: "12345678901234567890",
    publicKey: {
      p: CRYPTO_PARAMS.p,
      q: CRYPTO_PARAMS.q,
      g: CRYPTO_PARAMS.g,
      y: "987654321098765432109876543210",
    },
  };

  const secretKey = SecretKey.fromJSON(jsonData);

  // Verifica se os valores foram carregados corretamente do JSON
  assertEquals(secretKey.x.toString(), "12345678901234567890");
  assertEquals(secretKey.publicKey.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(secretKey.publicKey.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(secretKey.publicKey.g.toString(), CRYPTO_PARAMS.g);
  assertEquals(
    secretKey.publicKey.y.toString(),
    "987654321098765432109876543210",
  );
});

Deno.test("SecretKey::decryptionFactor", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Cria um plaintext e cifra
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const ciphertext = await pk.encrypt(plaintext);

  // Calcula o fator de decriptação
  const decFactor = sk.decryptionFactor(ciphertext);

  // Verifica se o fator de decriptação é um BigInteger válido
  assertEquals(decFactor instanceof BigInteger, true);

  // Verifica se o fator é igual a alpha^x mod p
  const expectedFactor = ciphertext.alpha.modPow(sk.x, pk.p);
  assertEquals(decFactor.toString(), expectedFactor.toString());
});

Deno.test("SecretKey::decryptionFactorAndProof", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Cria um plaintext e cifra
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const ciphertext = await pk.encrypt(plaintext);

  // Obtém o fator de decriptação e a prova
  const [decFactor, proof] = await sk.decryptionFactorAndProof(ciphertext);

  // Verifica se o fator e a prova foram gerados
  assertEquals(decFactor instanceof BigInteger, true);
  assertEquals(proof.commitment.A instanceof BigInteger, true);
  assertEquals(proof.commitment.B instanceof BigInteger, true);
  assertEquals(proof.challenge instanceof BigInteger, true);
  assertEquals(proof.response instanceof BigInteger, true);

  // Verifica se o fator é igual a alpha^x mod p
  const expectedFactor = ciphertext.alpha.modPow(sk.x, pk.p);
  assertEquals(decFactor.toString(), expectedFactor.toString());
});

Deno.test("SecretKey::decrypt", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Mensagem original
  const original = new BigInteger("12345");
  const plaintext = Plaintext.fromBigInteger(original);

  // Encripta a mensagem
  const ciphertext = await pk.encrypt(plaintext);

  // Decripta sem fornecer o fator de decriptação
  const decrypted1 = sk.decrypt(ciphertext);
  assert(decrypted1.equals(plaintext));

  // Decripta fornecendo o fator de decriptação
  const decFactor = sk.decryptionFactor(ciphertext);
  const decrypted2 = sk.decrypt(ciphertext, decFactor);
  assertEquals(decrypted2.m.toString(), original.toString());
});

Deno.test("SecretKey::decrypt com decode", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Mensagem original
  const original = new BigInteger("12345");
  const plaintext = Plaintext.fromBigInteger(original);

  // Encripta a mensagem com encode_message=true
  const ciphertext = pk.encryptWithR(plaintext, new BigInteger("54321"), true);

  // Decripta com decode=true
  const decrypted = sk.decrypt(ciphertext, null, true);

  // O resultado pode ser diferente do original devido à codificação/decodificação
  // Mas o importante é testar que o método não falha
  assert(decrypted instanceof Plaintext);
  assert(decrypted.m instanceof BigInteger);
  assert(decrypted.equals(plaintext)); // TODO??
});

Deno.test("SecretKey::proveDecryption", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Cria um plaintext e cifra
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const ciphertext = await pk.encrypt(plaintext);

  // Gera a prova de decriptação
  const [m, proof] = await sk.proveDecryption(ciphertext);

  // Verifica se m e a prova foram gerados
  assertEquals(m instanceof BigInteger, true);
  assertEquals(typeof proof, "object");
  assertEquals(typeof proof.commitment, "object");
  assertEquals(typeof proof.challenge, "string");
  assertEquals(typeof proof.response, "string");

  // m deve corresponder ao plaintext original
  assertEquals(m.toString(), plaintext.m.toString());
});

Deno.test("SecretKey::proveSk", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Gera uma prova de conhecimento da chave secreta
  const proof = await sk.proveSk(dLogChallengeGenerator);

  // Verifica se a prova foi gerada
  assertEquals(proof instanceof DLogProof, true);
  assertEquals(proof.commitment instanceof BigInteger, true);
  assertEquals(proof.challenge instanceof BigInteger, true);
  assertEquals(proof.response instanceof BigInteger, true);

  // Verifica se a prova pode ser validada pela chave pública
  const isValid = await pk.verifySkProof(proof, dLogChallengeGenerator);
  assert(isValid);
});

Deno.test("SecretKey::equals", async () => {
  const { pk, sk } = await system.generateKeyPair();

  // Cria uma nova chave secreta com os mesmos valores
  const sk2 = new SecretKey(sk.x, pk);
  assertEquals(sk.equals(sk2), true);

  // Altera o valor de x
  const sk3 = new SecretKey(sk.x.add(1), pk);
  assertEquals(sk.equals(sk3), false);
});

Deno.test("SecretKey::toJSON", async () => {
  const { sk } = await system.generateKeyPair();

  // Serializa para JSON
  const jsonOutput = sk.toJSON();

  // Verifica a estrutura do JSON
  assertEquals(typeof jsonOutput.x, "string");
  assertEquals(typeof jsonOutput.publicKey, "object");
  assertEquals(typeof jsonOutput.publicKey.p, "string");
  assertEquals(typeof jsonOutput.publicKey.q, "string");
  assertEquals(typeof jsonOutput.publicKey.g, "string");
  assertEquals(typeof jsonOutput.publicKey.y, "string");

  // Recria a partir do JSON
  const recreatedSk = SecretKey.fromJSON(jsonOutput);

  // Verifica se os valores foram preservados
  assertEquals(sk.equals(recreatedSk), true);
});

Deno.test("SecretKey::ciclo completo de encriptação/decriptação", async () => {
  const keyPair = await system.generateKeyPair();

  // Array de mensagens para testar
  const messages = ["Mensagem 1", "Outra mensagem", "123456789"];

  for (const message of messages) {
    // Cria plaintext a partir da mensagem
    const plaintext = await Plaintext.fromString(message);

    // Encripta com a chave pública
    const ciphertext = await keyPair.pk.encrypt(plaintext);

    // Decripta com a chave privada
    const decrypted = keyPair.sk.decrypt(ciphertext);

    // A mensagem decriptada deve corresponder à original
    assertEquals(await decrypted.compareToString(message), true);
  }
});
