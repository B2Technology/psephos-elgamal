import { BigInteger, getRandomBigInt, isProbablyPrime } from "./utils/index.ts";
import { KeyPair } from "./key-pair.ts";

export type CryptoSystemJSON = {
  p: string;
  q: string;
  g: string;
};

/**
 * p: Um número primo grande (normalmente 2048 bits ou mais nos dias atuais)
 * q: Um número primo que é divisor de p-1
 * g: Um gerador de um subgrupo cíclico de ordem q em Z*p
 */
export class CryptoSystem {
  constructor(
    private readonly p: BigInteger,
    private readonly q: BigInteger,
    private readonly g: BigInteger,
  ) {}

  /**
   * Gera parâmetros seguros para ElGamal e cria uma nova instância do CryptoSystem
   *
   * @param bitLength Tamanho em bits do primo p (recomendado 2048 ou maior)
   * @returns Promise com uma nova instância de CryptoSystem com parâmetros seguros
   */
  static async generateSecureParams(
    bitLength: number = 2048,
  ): Promise<CryptoSystem> {
    if (bitLength < 512) {
      throw new Error("Tamanho de bits muito pequeno para segurança adequada");
    }

    if (bitLength < 1024) {
      console.warn(
        "Recomenda-se um tamanho de bits de pelo menos 2048 para segurança adequada",
      );
    }

    // Gerar q primo (subgrupo)
    let q: BigInteger;
    do {
      q = await getRandomBigInt(256); // q deve ser grande o suficiente para segurança
    } while (!(await isProbablyPrime(q)));

    // Gerar p primo tal que p = 2*q*k + 1 para algum k
    let p: BigInteger;
    do {
      // Começamos com um k aleatório
      const k = await getRandomBigInt(bitLength - 256 - 1);
      // Calculamos p = 2*q*k + 1
      p = q.multiply(k).multiply(2).add(1);
      // Verificamos se p tem o tamanho desejado e é primo
    } while (p.bitLength() !== bitLength || !(await isProbablyPrime(p)));

    // Encontrar g como gerador de subgrupo de ordem q
    let g: BigInteger;
    do {
      // Escolher um número aleatório h entre 2 e p-2
      const h = new BigInteger(2).add(
        (await getRandomBigInt(bitLength - 2)).mod(p.subtract(3)),
      );

      // Calcular g = h^((p-1)/q) mod p
      const exp = p.subtract(1).divide(q);
      g = h.modPow(exp, p);

      // Garantir que g != 1
    } while (g.equals(1));

    return new CryptoSystem(p, q, g);
  }

  static fromJSON(data: CryptoSystemJSON): CryptoSystem {
    return new CryptoSystem(
      new BigInteger(data.p),
      new BigInteger(data.q),
      new BigInteger(data.g),
    );
  }

  generateKeyPair(): Promise<KeyPair> {
    return KeyPair.create(this.p, this.q, this.g);
  }

  generateKeyPairWithPrivateKey(x: string | BigInteger): KeyPair {
    const sk_x = new BigInteger(x);
    return KeyPair.createWithPrivateKey(this.p, this.q, this.g, sk_x);
  }

  toJSON(): CryptoSystemJSON {
    return {
      p: this.p.toString(),
      q: this.q.toString(),
      g: this.g.toString(),
    };
  }
}

/**
 * class Cryptosystem(object):
 *     def __init__(self):
 *       self.p = None
 *       self.q = None
 *       self.g = None
 *
 *     def generate_keypair(self):
 *       """
 *       generates a keypair in the setting
 *       """
 *
 *       keypair = KeyPair()
 *       keypair.generate(self.p, self.q, self.g)
 *
 *       return keypair
 */
