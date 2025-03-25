import { assert, assertEquals, assertFalse } from "jsr:@std/assert";
import { Commitment, CryptoSystem, Plaintext, ZKProof } from "../src/index.ts";
import {
  BigInteger,
  fiatShamirChallengeGenerator,
  type FiatShamirChallengeGeneratorFn,
} from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

// Função auxiliar para criar uma instância de ZKProof para testes
function createTestZKProof(): ZKProof {
  const commitment = new Commitment(
    new BigInteger("123456789"),
    new BigInteger("987654321"),
  );
  const challenge = new BigInteger("555555555");
  const response = new BigInteger("777777777");

  return new ZKProof(commitment, challenge, response);
}

// Função para simular um gerador de desafios para testes
const testChallengeGenerator: FiatShamirChallengeGeneratorFn = (
  _commitment: Commitment,
): Promise<BigInteger> => {
  return Promise.resolve(new BigInteger("555555555")); // Valor fixo para testes determinísticos
};

Deno.test("ZKProof::construtor", () => {
  const commitment = new Commitment(
    new BigInteger("123456789"),
    new BigInteger("987654321"),
  );
  const challenge = new BigInteger("555555555");
  const response = new BigInteger("777777777");

  const proof = new ZKProof(commitment, challenge, response);

  // Verifica se os valores foram atribuídos corretamente
  assert(proof.commitment.equals(commitment));
  assertEquals(proof.challenge.toString(), "555555555");
  assertEquals(proof.response.toString(), "777777777");
});

Deno.test("ZKProof::fromJSON", () => {
  const jsonData = {
    commitment: {
      A: "123456789",
      B: "987654321",
    },
    challenge: "555555555",
    response: "777777777",
  };

  const proof = ZKProof.fromJSON(jsonData);

  // Verifica se os valores foram carregados corretamente do JSON
  assertEquals(proof.commitment.A.toString(), "123456789");
  assertEquals(proof.commitment.B.toString(), "987654321");
  assertEquals(proof.challenge.toString(), "555555555");
  assertEquals(proof.response.toString(), "777777777");
});

Deno.test("ZKProof::equal", () => {
  const jsonData = {
    commitment: {
      A: "123456789",
      B: "987654321",
    },
    challenge: "555555555",
    response: "777777777",
  };

  const proof1 = ZKProof.fromJSON(jsonData);
  const proof2 = ZKProof.fromJSON(jsonData);
  const proof3 = ZKProof.fromJSON({ ...jsonData, challenge: "111111111" });

  // Verifica se os valores foram carregados corretamente do JSON
  assert(proof1.equals(proof2));
  assertFalse(proof1.equals(proof3));
});

Deno.test("ZKProof::generate", async () => {
  const littleG = new BigInteger(CRYPTO_PARAMS.g);
  const littleH = new BigInteger("123456789"); // Algum valor h para teste
  const x = new BigInteger("54321"); // Valor secreto para teste
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);

  // Gera uma prova
  const proof = await ZKProof.generate(
    littleG,
    littleH,
    x,
    p,
    q,
    testChallengeGenerator,
  );

  // Verifica se a prova foi gerada
  assertEquals(proof instanceof ZKProof, true);
  assertEquals(proof.commitment.A instanceof BigInteger, true);
  assertEquals(proof.commitment.B instanceof BigInteger, true);
  assertEquals(proof.challenge instanceof BigInteger, true);
  assertEquals(proof.response instanceof BigInteger, true);

  // Verifica se o desafio corresponde ao esperado do gerador de desafios
  assertEquals(proof.challenge.toString(), "555555555");

  // Verifica a equação da resposta: response = w + x*challenge mod q
  // É difícil verificar isso diretamente porque w é gerado aleatoriamente dentro do method
});

Deno.test("ZKProof::verify", async () => {
  const littleG = new BigInteger(CRYPTO_PARAMS.g);
  const littleH = new BigInteger("123456789"); // Algum valor h para teste
  const x = new BigInteger("54321"); // Valor secreto para teste
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);

  // Calcule bigG = littleG^x e bigH = littleH^x
  const bigG = littleG.modPow(x, p);
  const bigH = littleH.modPow(x, p);

  // Gera uma prova
  const proof = await ZKProof.generate(
    littleG,
    littleH,
    x,
    p,
    q,
    testChallengeGenerator,
  );

  // Verifica a prova
  const isValid = await proof.verify(
    littleG,
    littleH,
    bigG,
    bigH,
    p,
    q,
    testChallengeGenerator,
  );

  // A prova deve ser válida
  assertEquals(isValid, true);

  // Teste com valores inválidos
  const invalidBigG = littleG.modPow(new BigInteger("99999"), p);
  const isInvalid = await proof.verify(
    littleG,
    littleH,
    invalidBigG,
    bigH,
    p,
    q,
    testChallengeGenerator,
  );

  // A prova não deve ser válida com valores incorretos
  assertEquals(isInvalid, false);
});

Deno.test("ZKProof::verify sem verificador de desafio", async () => {
  const littleG = new BigInteger(CRYPTO_PARAMS.g);
  const littleH = new BigInteger("123456789"); // Algum valor h para teste
  const x = new BigInteger("54321"); // Valor secreto para teste
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);

  // Calcule bigG = littleG^x e bigH = littleH^x
  const bigG = littleG.modPow(x, p);
  const bigH = littleH.modPow(x, p);

  // Gera uma prova
  const proof = await ZKProof.generate(
    littleG,
    littleH,
    x,
    p,
    q,
    testChallengeGenerator,
  );

  // Verifica a prova sem o verificador de desafio
  const isValid = await proof.verify(
    littleG,
    littleH,
    bigG,
    bigH,
    p,
    q,
    null,
  );

  // A prova ainda deve ser válida mesmo sem verificar o desafio
  assertEquals(isValid, true);
});

Deno.test("ZKProof::toJSON", () => {
  const proof = createTestZKProof();

  // Converte para JSON
  const jsonOutput = proof.toJSON();

  // Verifica a estrutura do JSON
  assertEquals(typeof jsonOutput.commitment, "object");
  assertEquals(typeof jsonOutput.commitment.A, "string");
  assertEquals(typeof jsonOutput.commitment.B, "string");
  assertEquals(typeof jsonOutput.challenge, "string");
  assertEquals(typeof jsonOutput.response, "string");

  // Verifica os valores específicos
  assertEquals(jsonOutput.commitment.A, "123456789");
  assertEquals(jsonOutput.commitment.B, "987654321");
  assertEquals(jsonOutput.challenge, "555555555");
  assertEquals(jsonOutput.response, "777777777");

  // Verifica se é possível recriar o objeto a partir do JSON
  const recreated = ZKProof.fromJSON(jsonOutput);
  assert(recreated.commitment.equals(proof.commitment));
  assert(recreated.challenge.equals(proof.challenge));
  assert(recreated.response.equals(proof.response));
});

Deno.test("ZKProof::integração com sistema criptográfico", async () => {
  const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

  const keyPair = await system.generateKeyPair();

  // Mensagem a ser encriptada
  const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));

  // Encripta com um valor r conhecido
  const r = new BigInteger("54321");
  const ciphertext = keyPair.pk.encryptWithR(plaintext, r);

  // Gera uma prova de encriptação
  const proof = await ciphertext.generateEncryptionProof(
    r,
    fiatShamirChallengeGenerator,
  );

  // Verifica se a prova é válida
  const isValid = ciphertext.verifyEncryptionProof(plaintext, proof);
  assertEquals(isValid, true);

  // Verifica que a prova é do tipo ZKProof
  assertEquals(proof instanceof ZKProof, true);
});
