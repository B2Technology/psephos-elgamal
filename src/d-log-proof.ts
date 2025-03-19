import { BigInteger } from "./utils/index.ts";

/**
 * A classe DLogProof (Discrete Logarithm Proof) representa uma prova de conhecimento zero
 * para demonstrar que alguém conhece o logaritmo discreto de um valor, sem revelar esse valor secreto.
 *
 * commitment (comprometimento): Um BigInteger que representa um valor calculado como g^w mod p, onde w é um número aleatório escolhido pelo provador.
 * challenge (desafio): Um BigInteger gerado a partir do commitment, geralmente usando uma função hash determinística.
 * response (resposta): Um BigInteger calculado como w + x*challenge mod q, onde x é o valor secreto (o logaritmo discreto que está sendo provado).
 *
 * O objetivo desta classe é fornecer uma estrutura para provar o conhecimento do valor secreto x
 * (que geralmente é a chave privada) sem revelá-lo, seguindo o protocolo de prova de conhecimento zero Schnorr.
 *
 * Este tipo de prova é fundamental para sistemas criptográficos como ElGamal, permitindo verificar a posse de uma chave privada sem expô-la.
 * A classe DLogProof é usada principalmente pelo método `proveSk` na classe `SecretKey` para gerar provas de posse da chave privada,
 * e pelo método verifySkProof na classe PublicKey para verificar essas provas.
 */
export type DLogProofJSON = {
  commitment: string;
  challenge: string;
  response: string;
};

export class DLogProof {
  constructor(
    public readonly commitment: BigInteger,
    public readonly challenge: BigInteger,
    public readonly response: BigInteger,
  ) {}

  static fromJSON(data: DLogProofJSON): DLogProof {
    return new DLogProof(
      new BigInteger(data.commitment),
      new BigInteger(data.challenge),
      new BigInteger(data.response),
    );
  }

  toJSON(): DLogProofJSON {
    return {
      commitment: this.commitment.toString(),
      challenge: this.challenge.toString(),
      response: this.response.toString(),
    };
  }
}
