import {
  assert,
  assertEquals,
  assertFalse,
  assertNotEquals,
  assertThrows,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import {
  Ciphertext,
  Commitment,
  CryptoSystem,
  type KeyPair,
  Plaintext,
  ZKDisjunctiveProof,
  ZKProof,
} from "../src/index.ts";
import {
  BigInteger,
  disjunctiveChallengeGenerator,
  fiatShamirChallengeGenerator,
} from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

// Função auxiliar para criar um Ciphertext para testes
async function createTestCiphertext(keyPair?: KeyPair): Promise<Ciphertext> {
  if (!keyPair) {
    keyPair = await system.generateKeyPair();
  }

  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  return keyPair.pk.encrypt(plaintext);
}

Deno.test("Ciphertext::construtor", async () => {
  const keyPair = await system.generateKeyPair();
  const alpha = new BigInteger("123456789");
  const beta = new BigInteger("987654321");

  const ciphertext = new Ciphertext(alpha, beta, keyPair.pk);

  // Verifica se os valores foram atribuídos corretamente
  assertEquals(ciphertext.alpha.toString(), "123456789");
  assertEquals(ciphertext.beta.toString(), "987654321");
  assertEquals(ciphertext.pk, keyPair.pk);
});

Deno.test("Ciphertext::fromJSON", async () => {
  const keyPair = await system.generateKeyPair();

  const jsonData = {
    alpha: "123456789",
    beta: "987654321",
    pk: keyPair.pk.toJSON(),
  };

  const ciphertext = Ciphertext.fromJSON(jsonData);

  // Verifica se os valores foram carregados corretamente do JSON
  assertEquals(ciphertext.alpha.toString(), "123456789");
  assertEquals(ciphertext.beta.toString(), "987654321");
  assert(keyPair.pk.equals(ciphertext.pk));
});

Deno.test("Ciphertext::fromData", async () => {
  const keyPair = await system.generateKeyPair();

  const data = {
    alpha: "123456789",
    beta: "987654321",
  };

  const ciphertext = Ciphertext.fromData(data, keyPair.pk);

  // Verifica se os valores foram carregados corretamente
  assertEquals(ciphertext.alpha.toString(), "123456789");
  assertEquals(ciphertext.beta.toString(), "987654321");
  assert(keyPair.pk.equals(ciphertext.pk));
});

Deno.test("Ciphertext::fromString", async () => {
  const keyPair = await system.generateKeyPair();

  const str = "123456789,987654321";

  const ciphertext = Ciphertext.fromString(str, keyPair.pk);

  // Verifica se os valores foram carregados corretamente da string
  assertEquals(ciphertext.alpha.toString(), "123456789");
  assertEquals(ciphertext.beta.toString(), "987654321");
  assert(keyPair.pk.equals(ciphertext.pk));

  // Testa se o formato inválido causa erro
  assertThrows(
    () => {
      Ciphertext.fromString("apenas_um_valor", keyPair.pk);
    },
    Error,
    'Cannot convert "apenas_um_valor" to BigInteger',
  );

  // Testa se o formato inválido causa erro
  assertThrows(
    () => {
      Ciphertext.fromString("1", keyPair.pk);
    },
    Error,
    'Formato inválido para Ciphertext! Formato esperado: "${alpha},${beta}"',
  );
});

Deno.test("Ciphertext::multiply", async () => {
  const keyPair = await system.generateKeyPair();

  // Cria dois ciphertexts com a mesma chave pública
  const alpha1 = new BigInteger("1111");
  const beta1 = new BigInteger("2222");
  const ciphertext1 = new Ciphertext(alpha1, beta1, keyPair.pk);

  const alpha2 = new BigInteger("3333");
  const beta2 = new BigInteger("4444");
  const ciphertext2 = new Ciphertext(alpha2, beta2, keyPair.pk);

  // Multiplica os ciphertexts
  const result = ciphertext1.multiply(ciphertext2);

  // Verifica se o resultado é calculado corretamente
  assertEquals(
    result.alpha.toString(),
    alpha1.multiply(alpha2).mod(keyPair.pk.p).toString(),
  );
  assertEquals(
    result.beta.toString(),
    beta1.multiply(beta2).mod(keyPair.pk.p).toString(),
  );
  assert(result.pk.equals(keyPair.pk));

  // Testa multiplicação com diferentes chaves públicas (deve lançar erro)
  const differentKeyPair = await system.generateKeyPair();
  const ciphertext3 = new Ciphertext(alpha1, beta1, differentKeyPair.pk);

  assertThrows(
    () => {
      ciphertext1.multiply(ciphertext3);
    },
    Error,
    "Ciphertexts com chaves públicas diferentes",
  );

  // Quando passar valor 1 deve retornar o próprio ciphertext
  const result1 = ciphertext1.multiply(1);
  assert(result1.equals(ciphertext1));

  // Deve falhar ao tentar passar outro numero q nao seja 1 ou 0
  assertThrows(
    () => {
      ciphertext1.multiply(2);
    },
    Error,
    "invalid parameter type",
  );
});

Deno.test("Ciphertext::reencWithR", async () => {
  const keyPair = await system.generateKeyPair();
  const ciphertext = await createTestCiphertext(keyPair);

  const r = new BigInteger("54321");
  const reencrypted = ciphertext.reencWithR(r);

  // Verifica se o resultado é um Ciphertext
  assertEquals(reencrypted instanceof Ciphertext, true);

  // Verifica se os valores são diferentes dos originais (reencriptação)
  assertNotEquals(reencrypted.alpha.toString(), ciphertext.alpha.toString());
  assertNotEquals(reencrypted.beta.toString(), ciphertext.beta.toString());

  // Verifica se a chave pública permanece a mesma
  assert(reencrypted.pk.equals(ciphertext.pk));

  // Verifica se a mensagem pode ser decriptada corretamente
  const originalPlaintext = keyPair.sk.decrypt(ciphertext);
  const reencryptedPlaintext = keyPair.sk.decrypt(reencrypted);
  assertEquals(
    reencryptedPlaintext.m.toString(),
    originalPlaintext.m.toString(),
  );
});

Deno.test("Ciphertext::reencReturnR", async () => {
  const ciphertext = await createTestCiphertext();

  // Reencripta e retorna o valor r usado
  const [reencrypted, r] = await ciphertext.reencReturnR();

  // Verifica se o resultado contém um Ciphertext e um valor r
  assertEquals(reencrypted instanceof Ciphertext, true);
  assertEquals(r instanceof BigInteger, true);

  // Verifica se os valores são diferentes dos originais (reencriptação)
  assertFalse(reencrypted.equals(ciphertext));

  // Verifica se usando o mesmo r obtemos o mesmo resultado
  const manualReencrypted = ciphertext.reencWithR(r);
  assert(reencrypted.equals(manualReencrypted));
});

Deno.test("Ciphertext::reenc", async () => {
  const ciphertext = await createTestCiphertext();

  // Reencripta sem retornar r
  const reencrypted = await ciphertext.reenc();

  // Verifica se o resultado é um Ciphertext
  assertEquals(reencrypted instanceof Ciphertext, true);

  // Verifica se os valores são diferentes dos originais (reencriptação)
  assertNotEquals(reencrypted.alpha.toString(), ciphertext.alpha.toString());
  assertNotEquals(reencrypted.beta.toString(), ciphertext.beta.toString());
});

Deno.test("Ciphertext::decrypt", async () => {
  const keyPair = await system.generateKeyPair();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const ciphertext = await keyPair.pk.encrypt(plaintext);

  // Obtém fator de decriptação
  const decFactor = keyPair.sk.decryptionFactor(ciphertext);

  // Decripta usando o method decrypt do Ciphertext
  const decrypted = ciphertext.decrypt([decFactor], keyPair.pk);

  // Verifica se o resultado é o plaintext original
  assertEquals(decrypted.toString(), plaintext.m.toString());
});

Deno.test("Ciphertext::generateEncryptionProof", async () => {
  const keyPair = await system.generateKeyPair();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));

  // Encripta com um valor r conhecido
  const r = new BigInteger("54321");
  const ciphertext = keyPair.pk.encryptWithR(plaintext, r);

  // Gera uma prova de encriptação
  const proof = await ciphertext.generateEncryptionProof(
    r,
    fiatShamirChallengeGenerator,
  );

  // Verifica se a prova foi gerada
  assertEquals(proof instanceof ZKProof, true);
  assertEquals(proof.commitment.A instanceof BigInteger, true);
  assertEquals(proof.commitment.B instanceof BigInteger, true);
  assertEquals(proof.challenge instanceof BigInteger, true);
  assertEquals(proof.response instanceof BigInteger, true);

  // Verifica se a prova é válida
  const isValid = ciphertext.verifyEncryptionProof(plaintext, proof);
  assertEquals(isValid, true);
});

Deno.test("Ciphertext::verifyEncryptionProof", async () => {
  const keyPair = await system.generateKeyPair();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));

  // Encripta com um valor r conhecido
  const r = new BigInteger("54321");
  const ciphertext = keyPair.pk.encryptWithR(plaintext, r);

  // Gera uma prova de encriptação
  const validProof = await ciphertext.generateEncryptionProof(
    r,
    fiatShamirChallengeGenerator,
  );

  // Verifica a prova válida
  const isValid = ciphertext.verifyEncryptionProof(plaintext, validProof);
  assertEquals(isValid, true);

  // Testa com uma prova inválida
  const invalidProof = new ZKProof(
    new Commitment(new BigInteger("111"), new BigInteger("222")),
    new BigInteger("333"),
    new BigInteger("444"),
  );

  const isInvalid = ciphertext.verifyEncryptionProof(plaintext, invalidProof);
  assertEquals(isInvalid, false);
});

Deno.test("Ciphertext::simulateEncryptionProof", async () => {
  const keyPair = await system.generateKeyPair();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const ciphertext = await keyPair.pk.encrypt(plaintext);

  // Simula uma prova de encriptação
  const proof = await ciphertext.simulateEncryptionProof(plaintext);

  // Verifica se a prova foi gerada
  assertEquals(proof instanceof ZKProof, true);
  assertEquals(proof.commitment.A instanceof BigInteger, true);
  assertEquals(proof.commitment.B instanceof BigInteger, true);
  assertEquals(proof.challenge instanceof BigInteger, true);
  assertEquals(proof.response instanceof BigInteger, true);

  // Verifica se a prova simulada parece válida (mesmo sem ser gerada do modo normal)
  const isValid = ciphertext.verifyEncryptionProof(plaintext, proof);
  assertEquals(isValid, true);
});

Deno.test("Ciphertext::generateDisjunctiveEncryptionProof", async () => {
  const keyPair = await system.generateKeyPair();

  // Cria múltiplos plaintexts
  const plaintexts = [
    Plaintext.fromBigInteger(new BigInteger("11111")),
    Plaintext.fromBigInteger(new BigInteger("22222")),
    Plaintext.fromBigInteger(new BigInteger("33333")),
  ];

  // Encripta com um valor r conhecido
  const realIndex = 1; // O segundo plaintext é o real
  const r = new BigInteger("54321");
  const ciphertext = keyPair.pk.encryptWithR(plaintexts[realIndex], r);

  // Gera uma prova disjuntiva
  const proof = await ciphertext.generateDisjunctiveEncryptionProof(
    plaintexts,
    realIndex,
    r,
    disjunctiveChallengeGenerator,
  );

  // Verifica se a prova foi gerada
  assertEquals(proof instanceof ZKDisjunctiveProof, true);
  assertEquals(proof.proofs.length, plaintexts.length);

  // Verifica se a prova é válida
  const isValid = await ciphertext.verifyDisjunctiveEncryptionProof(
    plaintexts,
    proof,
    disjunctiveChallengeGenerator,
  );
  assertEquals(isValid, true);

  // TODO testar, como compro q marquei o index correto
});

Deno.test("Ciphertext::verifyDisjunctiveEncryptionProof", async () => {
  const keyPair = await system.generateKeyPair();

  // Cria múltiplos plaintexts
  const plaintexts = [
    Plaintext.fromBigInteger(new BigInteger("11111")),
    Plaintext.fromBigInteger(new BigInteger("22222")),
    Plaintext.fromBigInteger(new BigInteger("33333")),
  ];

  // Encripta com um valor r conhecido
  const realIndex = 1; // O segundo plaintext é o real
  const r = new BigInteger("54321");
  const ciphertext = keyPair.pk.encryptWithR(plaintexts[realIndex], r);

  // Gera uma prova disjuntiva válida
  const validProof = await ciphertext.generateDisjunctiveEncryptionProof(
    plaintexts,
    realIndex,
    r,
    disjunctiveChallengeGenerator,
  );

  // Verifica a prova válida
  const isValid = await ciphertext.verifyDisjunctiveEncryptionProof(
    plaintexts,
    validProof,
    disjunctiveChallengeGenerator,
  );
  assertEquals(isValid, true);

  // Testa com número incorreto de provas
  const fewerPlaintexts = [plaintexts[0], plaintexts[1]];
  const isInvalidCount = await ciphertext.verifyDisjunctiveEncryptionProof(
    fewerPlaintexts,
    validProof,
    disjunctiveChallengeGenerator,
  );
  assertEquals(isInvalidCount, false);
});

Deno.test("Ciphertext::equals", async () => {
  const keyPair = await system.generateKeyPair();

  // Cria dois ciphertexts idênticos
  const alpha = new BigInteger("123456789");
  const beta = new BigInteger("987654321");
  const ciphertext1 = new Ciphertext(alpha, beta, keyPair.pk);
  const ciphertext2 = new Ciphertext(alpha, beta, keyPair.pk);

  // Cria um ciphertext diferente
  const ciphertext3 = new Ciphertext(
    new BigInteger("111111"),
    beta,
    keyPair.pk,
  );

  // Testa igualdade
  assertEquals(ciphertext1.equals(ciphertext2), true);
  assertEquals(ciphertext1.equals(ciphertext3), false);
  assertEquals(ciphertext1.equals(null), false);
});

Deno.test("Ciphertext::toString", async () => {
  const keyPair = await system.generateKeyPair();
  const alpha = new BigInteger("123456789");
  const beta = new BigInteger("987654321");

  const ciphertext = new Ciphertext(alpha, beta, keyPair.pk);

  // Testa o formato de string
  const str = ciphertext.toString();
  assertEquals(str, "123456789,987654321");

  // Verifica se é possível recriar o objeto a partir da string
  const recreated = Ciphertext.fromString(str, keyPair.pk);
  assert(recreated.equals(ciphertext));
});

Deno.test("Ciphertext::toJSON", async () => {
  const keyPair = await system.generateKeyPair();
  const alpha = new BigInteger("123456789");
  const beta = new BigInteger("987654321");

  const ciphertext = new Ciphertext(alpha, beta, keyPair.pk);

  // Testa a serialização para JSON
  const jsonOutput = ciphertext.toJSON();

  // Verifica a estrutura do JSON
  assertEquals(typeof jsonOutput.alpha, "string");
  assertEquals(typeof jsonOutput.beta, "string");
  assertEquals(typeof jsonOutput.pk, "object");

  // Verifica os valores específicos
  assertEquals(jsonOutput.alpha, "123456789");
  assertEquals(jsonOutput.beta, "987654321");

  // Verifica se é possível recriar o objeto a partir do JSON
  const recreated = Ciphertext.fromJSON(jsonOutput);
  assert(recreated.equals(ciphertext));
});

Deno.test("Ciphertext::toCommitmentJSON", async () => {
  const keyPair = await system.generateKeyPair();
  const alpha = new BigInteger("123456789");
  const beta = new BigInteger("987654321");

  const ciphertext = new Ciphertext(alpha, beta, keyPair.pk);

  // Testa a serialização para JSON
  const jsonOutput = ciphertext.toCommitmentJSON();

  // Verifica a estrutura do JSON
  assertEquals(typeof jsonOutput.alpha, "string");
  assertEquals(typeof jsonOutput.beta, "string");

  // Verifica os valores específicos
  assertEquals(jsonOutput.alpha, "123456789");
  assertEquals(jsonOutput.beta, "987654321");
});
