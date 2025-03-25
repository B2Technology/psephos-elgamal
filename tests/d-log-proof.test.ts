import { assertEquals } from "jsr:@std/assert";
import { BigInteger } from "../src/utils/index.ts";
import { DLogProof } from "../src/index.ts";

// Função auxiliar para criar um DLogProof para testes
function createTestDLogProof(): DLogProof {
  const commitment = new BigInteger("123456789");
  const challenge = new BigInteger("987654321");
  const response = new BigInteger("567891234");

  return new DLogProof(commitment, challenge, response);
}

Deno.test("DLogProof::construtor", () => {
  const commitment = new BigInteger("123456789");
  const challenge = new BigInteger("987654321");
  const response = new BigInteger("567891234");

  const proof = new DLogProof(commitment, challenge, response);

  assertEquals(proof.commitment.toString(), "123456789");
  assertEquals(proof.challenge.toString(), "987654321");
  assertEquals(proof.response.toString(), "567891234");
});

Deno.test("DLogProof::fromJSON", () => {
  const jsonData = {
    commitment: "123456789",
    challenge: "987654321",
    response: "567891234",
  };

  const proof = DLogProof.fromJSON(jsonData);

  assertEquals(proof.commitment.toString(), "123456789");
  assertEquals(proof.challenge.toString(), "987654321");
  assertEquals(proof.response.toString(), "567891234");
});

Deno.test("DLogProof::toJSON", () => {
  const proof = createTestDLogProof();
  const jsonOutput = proof.toJSON();

  assertEquals(jsonOutput.commitment, "123456789");
  assertEquals(jsonOutput.challenge, "987654321");
  assertEquals(jsonOutput.response, "567891234");

  // Verifica ciclo de serialização/deserialização
  const recreatedProof = DLogProof.fromJSON(jsonOutput);
  assertEquals(
    recreatedProof.commitment.toString(),
    proof.commitment.toString(),
  );
  assertEquals(recreatedProof.challenge.toString(), proof.challenge.toString());
  assertEquals(recreatedProof.response.toString(), proof.response.toString());
});
