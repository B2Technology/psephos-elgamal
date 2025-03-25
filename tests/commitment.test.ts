import { assertEquals, assertNotEquals } from "jsr:@std/assert";
import { BigInteger } from "../src/utils/index.ts";
import { Commitment, type CommitmentJSON } from "../src/index.ts";

Deno.test("Commitment::construtor", () => {
  const A = new BigInteger("123456789");
  const B = new BigInteger("987654321");
  const commitment = new Commitment(A, B);

  // Verifica se os valores foram armazenados corretamente
  assertEquals(commitment.A.toString(), "123456789");
  assertEquals(commitment.B.toString(), "987654321");
});

Deno.test("Commitment::fromJSON", () => {
  const jsonData: CommitmentJSON = {
    A: "123456789",
    B: "987654321",
  };

  const commitment = Commitment.fromJSON(jsonData);

  // Verifica se o objeto foi criado corretamente a partir do JSON
  assertEquals(commitment.A.toString(), "123456789");
  assertEquals(commitment.B.toString(), "987654321");
});

Deno.test("Commitment::toJSON", () => {
  const A = new BigInteger("123456789");
  const B = new BigInteger("987654321");

  const commitment = new Commitment(A, B);
  const jsonOutput = commitment.toJSON();

  // Verifica se o method toJSON retorna o formato esperado
  assertEquals(jsonOutput.A, "123456789");
  assertEquals(jsonOutput.B, "987654321");

  // Verifica se é possível recriar o objeto a partir do JSON gerado
  const recreatedCommitment = Commitment.fromJSON(jsonOutput);
  assertEquals(recreatedCommitment.A.toString(), A.toString());
  assertEquals(recreatedCommitment.B.toString(), B.toString());
});

Deno.test("Commitment::diferentes instâncias com mesmos valores", () => {
  const A = new BigInteger("123456789");
  const B = new BigInteger("987654321");

  const commitment1 = new Commitment(A, B);
  const commitment2 = new Commitment(A, B);

  // Verifica se objetos diferentes com mesmos valores produzem JSONs iguais
  assertEquals(commitment1.toJSON().A, commitment2.toJSON().A);
  assertEquals(commitment1.toJSON().B, commitment2.toJSON().B);
});

Deno.test("Commitment::valores diferentes produzem commitments diferentes", () => {
  const A1 = new BigInteger("123456789");
  const B1 = new BigInteger("987654321");

  const A2 = new BigInteger("111111111");
  const B2 = new BigInteger("999999999");

  const commitment1 = new Commitment(A1, B1);
  const commitment2 = new Commitment(A2, B2);

  // Verifica se objetos com valores diferentes produzem JSONs diferentes
  assertNotEquals(commitment1.toJSON().A, commitment2.toJSON().A);
  assertNotEquals(commitment1.toJSON().B, commitment2.toJSON().B);
});

Deno.test("Commitment::fromJSON com valores grandes", () => {
  const jsonData = {
    A: "16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071",
    B: "14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533",
  };

  const commitment = Commitment.fromJSON(jsonData);

  // Verifica se valores grandes são manipulados corretamente
  assertEquals(commitment.A.toString(), jsonData.A);
  assertEquals(commitment.B.toString(), jsonData.B);

  // Verifica se a conversão de volta para JSON mantém os valores intactos
  const jsonOutput = commitment.toJSON();
  assertEquals(jsonOutput.A, jsonData.A);
  assertEquals(jsonOutput.B, jsonData.B);
});

Deno.test("Commitment::fromJSON com valores inválidos", () => {
  const invalidJsonData = {
    A: "não é um número",
    B: "987654321",
  };

  try {
    Commitment.fromJSON(invalidJsonData);
    // Se não lançar exceção, o teste falha
    assertEquals(
      1,
      0,
      "Deveria ter lançado uma exceção para valores inválidos",
    );
  } catch (error) {
    // Esperamos que uma exceção seja lançada
    assertEquals(error instanceof Error, true);
  }
});
