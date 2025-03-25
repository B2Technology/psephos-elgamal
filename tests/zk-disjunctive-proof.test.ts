import { assert, assertEquals, assertThrows } from "jsr:@std/assert";
import {
  Commitment,
  CryptoSystem,
  Plaintext,
  ZKDisjunctiveProof,
  ZKProof,
  type ZKProofJSON,
} from "../src/index.ts";
import {
  BigInteger,
  disjunctiveChallengeGenerator,
} from "../src/utils/index.ts";
import { CRYPTO_PARAMS } from "./stubs/contants.ts";

const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

// Função auxiliar para criar provas individuais para testes
function createTestZKProofs(count: number): ZKProof[] {
  const proofs: ZKProof[] = [];

  for (let i = 0; i < count; i++) {
    const commitment = new Commitment(
      new BigInteger(`${1000 + i}`),
      new BigInteger(`${2000 + i}`),
    );
    const challenge = new BigInteger(`${3000 + i}`);
    const response = new BigInteger(`${4000 + i}`);

    proofs.push(new ZKProof(commitment, challenge, response));
  }

  return proofs;
}

// Função para criar uma prova disjuntiva real usando o sistema criptográfico
async function createRealDisjunctiveProof(): Promise<ZKDisjunctiveProof> {
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
  return ciphertext.generateDisjunctiveEncryptionProof(
    plaintexts,
    realIndex,
    r,
    disjunctiveChallengeGenerator,
  );
}

Deno.test("ZKDisjunctiveProof::construtor", () => {
  const proofs = createTestZKProofs(3);
  const disjunctiveProof = new ZKDisjunctiveProof(proofs);

  // Verifica se os proofs foram armazenados corretamente
  assertEquals(disjunctiveProof.proofs.length, 3);
  assert(disjunctiveProof.proofs[0].equals(proofs[0]));
  assert(disjunctiveProof.proofs[1].equals(proofs[1]));
  assert(disjunctiveProof.proofs[2].equals(proofs[2]));
});

Deno.test("ZKDisjunctiveProof::fromJsonProofs", () => {
  const proofs = createTestZKProofs(3);
  const jsonProofs = proofs.map((p) => p.toJSON());

  const disjunctiveProof = ZKDisjunctiveProof.fromJsonProofs(jsonProofs);

  // Verifica se os proofs foram carregados corretamente do JSON
  assertEquals(disjunctiveProof.proofs.length, 3);

  for (let i = 0; i < 3; i++) {
    assert(disjunctiveProof.proofs[i].equals(proofs[i]));
  }
});

Deno.test("ZKDisjunctiveProof::fromJsonProofs com dados inválidos", () => {
  // Testa com dados null
  assertThrows(
    () => ZKDisjunctiveProof.fromJsonProofs(null as unknown as ZKProofJSON[]),
    Error,
    "Invalid proofs!",
  );

  // Testa com dados não-array
  assertThrows(
    () => ZKDisjunctiveProof.fromJsonProofs({} as ZKProofJSON[]),
    Error,
    "Invalid proofs!",
  );
});

Deno.test("ZKDisjunctiveProof::toJSON", () => {
  const proofs = createTestZKProofs(3);
  const disjunctiveProof = new ZKDisjunctiveProof(proofs);

  // Converte para JSON
  const jsonOutput = disjunctiveProof.toJSON();

  // Verifica a estrutura do JSON
  assertEquals(Array.isArray(jsonOutput.proofs), true);
  assertEquals(jsonOutput.proofs.length, 3);

  // Verifica se os valores foram serializados corretamente
  for (let i = 0; i < 3; i++) {
    assertEquals(jsonOutput.proofs[i].commitment.A, `${1000 + i}`);
    assertEquals(jsonOutput.proofs[i].commitment.B, `${2000 + i}`);
    assertEquals(jsonOutput.proofs[i].challenge, `${3000 + i}`);
    assertEquals(jsonOutput.proofs[i].response, `${4000 + i}`);
  }

  // Verifica se é possível recriar o objeto a partir do JSON
  const recreated = ZKDisjunctiveProof.fromJsonProofs(jsonOutput.proofs);
  assertEquals(recreated.proofs.length, disjunctiveProof.proofs.length);

  for (let i = 0; i < 3; i++) {
    assert(recreated.proofs[i].equals(disjunctiveProof.proofs[i]));
  }
});

Deno.test("ZKDisjunctiveProof::integração com Ciphertext", async () => {
  const disjunctiveProof = await createRealDisjunctiveProof();

  // Verifica que a prova foi criada
  assertEquals(disjunctiveProof instanceof ZKDisjunctiveProof, true);
  assertEquals(disjunctiveProof.proofs.length, 3);

  // Verifica que cada prova interna tem a estrutura correta
  for (const proof of disjunctiveProof.proofs) {
    assertEquals(proof instanceof ZKProof, true);
    assertEquals(proof.commitment instanceof Commitment, true);
    assertEquals(proof.challenge instanceof BigInteger, true);
    assertEquals(proof.response instanceof BigInteger, true);
  }

  // Serializa e deserializa para testar o ciclo completo
  const jsonData = disjunctiveProof.toJSON();
  const recreated = ZKDisjunctiveProof.fromJsonProofs(jsonData.proofs);

  assertEquals(recreated.proofs.length, disjunctiveProof.proofs.length);
});

Deno.test("ZKDisjunctiveProof::verificação de soma de desafios", async () => {
  const disjunctiveProof = await createRealDisjunctiveProof();

  // A soma dos desafios deve ser igual ao desafio disjuntivo gerado pelos commitments
  const commitments = disjunctiveProof.proofs.map((p) => p.commitment);
  const expectedChallenge = await disjunctiveChallengeGenerator(commitments);

  let sumChallenges = BigInteger.ZERO;
  for (const proof of disjunctiveProof.proofs) {
    sumChallenges = sumChallenges.add(proof.challenge);
  }
  sumChallenges = sumChallenges.mod(new BigInteger(CRYPTO_PARAMS.q));

  // Verifica se a soma dos desafios é igual ao desafio esperado
  assertEquals(sumChallenges.toString(), expectedChallenge.toString());
});
