import {
  assert,
  assertEquals,
  assertFalse,
  assertNotEquals,
  assertThrows,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import {
  Ciphertext,
  CryptoSystem,
  Plaintext,
  PublicKey,
  type PublicKeyJSON,
} from "../src/index.ts";
import {
  BigInteger,
  dLogChallengeGenerator,
  type DLogChallengeGeneratorFn,
} from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

// Gera uma instância de PublicKey para testes
async function createTestPublicKey(): Promise<PublicKey> {
  const keyPair = await system.generateKeyPair();
  return keyPair.pk;
}

Deno.test("PublicKey::construtor", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);
  const y = new BigInteger("123456789");

  const publicKey = new PublicKey(p, q, g, y);

  // Verifica se os valores foram atribuídos corretamente
  assertEquals(publicKey.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(publicKey.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(publicKey.g.toString(), CRYPTO_PARAMS.g);
  assertEquals(publicKey.y.toString(), "123456789");
});

Deno.test("PublicKey::fromJSON", () => {
  const jsonData: PublicKeyJSON = {
    p: CRYPTO_PARAMS.p,
    q: CRYPTO_PARAMS.q,
    g: CRYPTO_PARAMS.g,
    y: "123456789",
  };

  const publicKey = PublicKey.fromJSON(jsonData);

  // Verifica se os valores foram carregados corretamente do JSON
  assertEquals(publicKey.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(publicKey.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(publicKey.g.toString(), CRYPTO_PARAMS.g);
  assertEquals(publicKey.y.toString(), "123456789");
});

Deno.test("PublicKey::encryptWithR e decrypt", async () => {
  const keyPair = await system.generateKeyPair();

  // Mensagem a ser encriptada
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const r = new BigInteger("54321"); // Valor de randomness fixo para teste determinístico

  // Encripta usando a chave pública com valor r fixo
  const ciphertext = keyPair.pk.encryptWithR(plaintext, r);

  // Decripta usando a chave privada
  const decryptedPlaintext = keyPair.sk.decrypt(ciphertext);

  // Verifica se a mensagem decriptada é igual à original
  assertEquals(decryptedPlaintext.m.toString(), plaintext.m.toString());

  // Verifica se os mesmos parâmetros de entrada sempre produzem o mesmo ciphertext
  const ciphertext2 = keyPair.pk.encryptWithR(plaintext, r);
  assert(ciphertext.equals(ciphertext2));

  // Verifica se r diferente produz ciphertexts diferentes
  const r3 = new BigInteger("54322");
  const ciphertext3 = keyPair.pk.encryptWithR(plaintext, r3);
  assertFalse(ciphertext.equals(ciphertext3));
});

Deno.test("PublicKey::encryptReturnR", async () => {
  const publicKey = await createTestPublicKey();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));

  // Encripta e retorna o valor r usado
  const [ciphertext, r] = await publicKey.encryptReturnR(plaintext);

  // Verifica se ciphertext e r são retornados
  assertEquals(ciphertext instanceof Ciphertext, true);
  assertEquals(r instanceof BigInteger, true);

  // Recria o ciphertext usando o r retornado para verificar consistência
  const recreatedCiphertext = publicKey.encryptWithR(plaintext, r);
  assertEquals(
    ciphertext.alpha.toString(),
    recreatedCiphertext.alpha.toString(),
  );
  assertEquals(ciphertext.beta.toString(), recreatedCiphertext.beta.toString());

  // Verifica se r e ciphertext é diferente a cada chamada
  const [ciphertext2, r2] = await publicKey.encryptReturnR(plaintext);
  assertNotEquals(r.toString(), r2.toString());
  assertFalse(ciphertext2.equals(ciphertext));
});

Deno.test("PublicKey::encrypt", async () => {
  const publicKey = await createTestPublicKey();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));

  // Encripta sem retornar r
  const ciphertext = await publicKey.encrypt(plaintext);

  // Verifica se o ciphertext foi criado
  assertEquals(ciphertext instanceof Ciphertext, true);

  // Verificações básicas no ciphertext
  assertEquals(ciphertext.pk, publicKey);
  assertNotEquals(ciphertext.alpha.toString(), "0");
  assertNotEquals(ciphertext.beta.toString(), "0");

  // Mesmo plaintext deve produzir ciphertexts diferentes
  const ciphertext2 = await publicKey.encrypt(plaintext);
  assertFalse(ciphertext2.equals(ciphertext));
});

// TODO revisar
// Deno.test("PublicKey::generateProof", async () => {
//   const publicKey = await createTestPublicKey();
//   const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
//   const ciphertext = await publicKey.encrypt(plaintext);
//
//   // Gera uma prova de conhecimento da encriptação
//   const proof = await publicKey.generateProof(plaintext);
//
//   // Verifica se a prova foi criada
//   assertEquals(proof instanceof ZKProof, true);
//
//   // Verifica a estrutura da prova
//   assertEquals(proof.commitment.A instanceof BigInteger, true);
//   assertEquals(proof.commitment.B instanceof BigInteger, true);
//   assertEquals(proof.challenge instanceof BigInteger, true);
//   assertEquals(proof.response instanceof BigInteger, true);
//
//   // Agora, verifique se a prova é válida
//   const isValid =  ciphertext.verifyEncryptionProof(plaintext, proof);
//   assert(isValid,"A prova é válida?");
// });

Deno.test("PublicKey::multiply", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);

  const y1 = new BigInteger("123456789");
  const y2 = new BigInteger("987654321");

  const pk1 = new PublicKey(p, q, g, y1);
  const pk2 = new PublicKey(p, q, g, y2);

  // Multiplica duas chaves públicas
  const combinedPk = pk1.multiply(pk2);

  // Verifica se os parâmetros criptográficos são mantidos
  assertEquals(combinedPk.p.toString(), p.toString());
  assertEquals(combinedPk.q.toString(), q.toString());
  assertEquals(combinedPk.g.toString(), g.toString());

  // Verifica se y é o produto de y1 e y2 mod p
  const expectedY = y1.multiply(y2).mod(p);
  assertEquals(combinedPk.y.toString(), expectedY.toString());

  // Se multiplicar por 1 deve retornar a mesma chave
  const pk3 = combinedPk.multiply(1);
  assertEquals(pk3.equals(combinedPk), true);

  // Nao deve ser possível multiplicar chaves de outros sistemas
  const pk4 = new PublicKey(p, q, g.add(2), y2);
  assertThrows(
    () => {
      pk1.multiply(pk4);
    },
    Error,
    "incompatible public keys",
  );

  // Deve falhar ao tentar passar outro numero q nao seja 1 ou 0
  assertThrows(
    () => {
      pk1.multiply(2);
    },
    Error,
    "invalid parameter type",
  );
});

Deno.test("PublicKey::verifySkProof", async () => {
  const keyPair = await system.generateKeyPair();

  // Gera uma prova de conhecimento da chave secreta
  const proof = await keyPair.sk.proveSk(dLogChallengeGenerator);

  // Verifica a prova usando a chave pública
  const isValid = await keyPair.pk.verifySkProof(proof, dLogChallengeGenerator);
  assert(isValid);

  // Uma prova verificada com uma função diferente deve falhar
  const differentGenerator: DLogChallengeGeneratorFn = (
    commitment: BigInteger,
  ) => Promise.resolve(commitment.add(2));

  const isInvalid = await keyPair.pk.verifySkProof(proof, differentGenerator);
  assertFalse(isInvalid);
});

Deno.test("PublicKey::fingerprint", async () => {
  const publicKey = await createTestPublicKey();
  const fingerprint = await publicKey.fingerprint();

  // Verifica se o fingerprint foi gerado
  assertEquals(typeof fingerprint, "string");
  assertEquals(fingerprint.length > 0, true);

  // O mesmo objeto publicKey deve sempre gerar o mesmo fingerprint
  const fingerprint2 = await publicKey.fingerprint();
  assertEquals(fingerprint, fingerprint2);

  // Diferentes chaves devem gerar diferentes fingerprints
  const differentKey = await createTestPublicKey();
  const differentFingerprint = await differentKey.fingerprint();
  assertNotEquals(fingerprint, differentFingerprint);
});

Deno.test("PublicKey::equals", () => {
  const publicKey1 = system.generateKeyPairWithPrivateKey("123456789").pk;
  const publicKey2 = system.generateKeyPairWithPrivateKey("123456789").pk;
  const publicKey3 = system.generateKeyPairWithPrivateKey("1234").pk;

  // Verifica se duas chaves públicas são iguais
  assert(publicKey1.equals(publicKey2));

  // Comparação com chaves diferentes
  assertFalse(publicKey1.equals(publicKey3));
});

Deno.test("PublicKey::toJSON", async () => {
  const publicKey = await createTestPublicKey();
  const jsonOutput = publicKey.toJSON();

  // Verifica a estrutura do JSON
  assertEquals(typeof jsonOutput.p, "string");
  assertEquals(typeof jsonOutput.q, "string");
  assertEquals(typeof jsonOutput.g, "string");
  assertEquals(typeof jsonOutput.y, "string");

  // Verifica os valores específicos
  assertEquals(jsonOutput.p, CRYPTO_PARAMS.p);
  assertEquals(jsonOutput.q, CRYPTO_PARAMS.q);
  assertEquals(jsonOutput.g, CRYPTO_PARAMS.g);
});

Deno.test("PublicKey::verifySkProof tentar com uma chave diferente", async () => {
  const keyPair1 = await system.generateKeyPair();
  const keyPair2 = await system.generateKeyPair();

  const proof1 = await keyPair1.sk.proveSk(dLogChallengeGenerator);

  const isValid = await keyPair2.pk.verifySkProof(
    proof1,
    dLogChallengeGenerator,
  );
  assertFalse(isValid);
});

Deno.test("PublicKey::encryptWithR com encode_message", async () => {
  const publicKey = await createTestPublicKey();
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
  const r = new BigInteger("54321");

  // Encripta com encode_message = true
  const ciphertext = publicKey.encryptWithR(plaintext, r, true);

  // Verifica se o ciphertext foi criado
  assertEquals(ciphertext instanceof Ciphertext, true);

  // O ciphertext deve ser diferente do gerado sem encode_message
  const regularCiphertext = publicKey.encryptWithR(plaintext, r, false);
  assertNotEquals(
    ciphertext.beta.toString(),
    regularCiphertext.beta.toString(),
  );
});
