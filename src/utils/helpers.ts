import type { Commitment } from "../commitment.ts";
import type { ChallengeGeneratorByCommitFn } from "../types.ts";
import { BigInteger } from "./big-Integer.ts";

// TODO revisar e testar todos estes metodos

/**
 * Gera bytes aleatórios criptograficamente seguros usando a Web Crypto API
 * @returns String hexadecimal dos bytes aleatórios
 * @param length
 */
export function getRandomBytes(length: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return Promise.resolve(bytes);
  // TODO refactor
  // if (isDeno) {
  //   crypto.getRandomValues(bytes);
  // } else if (isNode) {
  //   const nodeCrypto = await import("crypto");
  //   const randomBytes = nodeCrypto.randomBytes(length);
  //   bytes.set(new Uint8Array(randomBytes.buffer));
  // } else if (isBrowser) {
  //   crypto.getRandomValues(bytes);
  // } else {
  //   throw new Error("Unsupported environment");
  // }
  //
  // return Promise.resolve(bytes);
}

export async function randomMpzLt(_maximum: BigInteger): Promise<BigInteger> {
  const max = _maximum.valueOf();
  const nBits = Math.floor(Math.log2(Number(max))) + 1;
  const numBytes = Math.ceil(nBits / 8);
  let res: bigint;

  do {
    const randomBytes = await getRandomBytes(numBytes);
    const randomHex = Array.from(randomBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    res = BigInt(`0x${randomHex}`);
  } while (res >= max);

  return new BigInteger(res);
}

// TODO ver se a funcao "utils/textToBigInt" nao faz a mesma coisa (se nao for, mover isso para dentro de utils fora da pasta elgamal)
export async function sha1ToBigInt(stringToHash: string): Promise<BigInteger> {
  const encoder = new TextEncoder();
  const data = encoder.encode(stringToHash);

  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(
    "",
  );

  const num = BigInt(`0x${hashHex}`).toString();

  return new BigInteger(num);
}

export function disjunctiveChallengeGenerator(
  commitments: Commitment[],
): Promise<BigInteger> {
  const arrayToHash: string[] = [];
  for (const commitment of commitments) {
    arrayToHash.push(String(commitment.A));
    arrayToHash.push(String(commitment.B));
  }

  const stringToHash = arrayToHash.join(",");
  return sha1ToBigInt(stringToHash);
}

export const fiatshamirChallengeGenerator: ChallengeGeneratorByCommitFn = (
  commitment: Commitment,
): Promise<BigInteger> => {
  return disjunctiveChallengeGenerator([commitment]);
};

// TODO analisar e remover caso nao usar
export function DLogChallengeGenerator(
  commitment: string,
): Promise<BigInteger> {
  return sha1ToBigInt(String(commitment));
}

// export const simpleChallengeGeneratorFn: ChallengeGeneratorByBigIntFn = (
//   commitment: BigInteger,
// ): Promise<BigInteger> => {
//   //
//   return Promise.resolve(commitment)
// };

// TODO ver para unificar com randomMpzLt
export function getRandomBigInt(bits: number): Promise<BigInteger> {
  const bytes = Math.ceil(bits / 8);
  const randomBytes = new Uint8Array(bytes);

  globalThis.crypto.getRandomValues(randomBytes);

  const hexString = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const bigInt = new BigInteger(`0x${hexString}`);

  // Garantindo que o número tem exatamente o número de bits solicitado
  // Definimos o bit mais significativo para 1
  const mask = new BigInteger(2).pow(bits - 1);
  return Promise.resolve(bigInt.mod(new BigInteger(2).pow(bits)).add(mask));
}

// Função para verificar se um número é provavelmente primo
export async function isProbablyPrime(
  n: BigInteger,
  k: number = 10,
): Promise<boolean> {
  // Implementação do teste de Miller-Rabin
  // Para números pequenos, verificamos diretamente
  if (n.equals(2) || n.equals(3)) return true;
  if (n.mod(2).equals(0)) return false;

  const nMinus1 = n.subtract(1);
  let r = 0;
  let d = nMinus1;

  // Encontrar r e d tal que n-1 = 2^r * d, onde d é ímpar
  while (d.mod(2).equals(0)) {
    r++;
    d = d.divide(2);
  }

  // Teste de Miller-Rabin
  witnessLoop: for (let i = 0; i < k; i++) {
    // Escolher um número aleatório a no intervalo [2, n-2]
    let a: BigInteger;
    do {
      a = await getRandomBigInt(n.bitLength() - 1);
    } while (a.compareTo(2) < 0 || a.compareTo(nMinus1) >= 0);

    let x = a.modPow(d, n);
    if (x.equals(1) || x.equals(nMinus1)) continue;

    for (let j = 0; j < r - 1; j++) {
      x = x.modPow(2, n);
      if (x.equals(nMinus1)) continue witnessLoop;
      if (x.equals(1)) return false;
    }

    x = x.modPow(2, n);
    if (!x.equals(1)) return false;
  }

  return true;
}
