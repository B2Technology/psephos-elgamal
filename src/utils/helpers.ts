import type { PublicKey } from "../public-key.ts";
import { BigInteger } from "./big-Integer.ts";
import { Plaintext } from "../plaintext.ts";

// TODO criar tests unitários para essas funções

/**
 * Gera bytes aleatórios criptograficamente seguros usando a Web Crypto API
 * @returns String hexadecimal dos bytes aleatórios
 * @param length
 */
export function randomBytes(length: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return Promise.resolve(bytes);
}

export async function randomMpzLt(_maximum: BigInteger): Promise<BigInteger> {
  const max = _maximum.valueOf();
  const nBits = Math.floor(Math.log2(Number(max))) + 1;
  const numBytes = Math.ceil(nBits / 8);
  let res: bigint;

  do {
    const rnBytes = await randomBytes(numBytes);
    const randomHex = Array.from(rnBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    res = BigInt(`0x${randomHex}`);
  } while (res >= max);

  return new BigInteger(res);
}

export function randomBigInt(bits: number): Promise<BigInteger> {
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
      a = await randomBigInt(n.bitLength() - 1);
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

export async function sha1(stringToHash: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(stringToHash);

  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha1ToBigInt(stringToHash: string): Promise<BigInteger> {
  const hashHex = await sha1(stringToHash);
  const num = BigInt(`0x${hashHex}`).toString();
  return new BigInteger(num);
}

export async function sha1Fingerprint(stringToHash: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(stringToHash);

  // Calcula o hash SHA1 da string
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  return Array.from(hashArray)
    .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
    .join(":");
}
// Função para verificar se um número é provavelmente primo

export function generatePlaintexts(
  pk: PublicKey,
  min: number,
  max: number,
): Plaintext[] {
  let last_plaintext = BigInteger.ONE;

  // an array of plaintexts
  const plaintexts: Array<Plaintext> = [];

  if (min == null) min = 0;

  // questions with more than one possible answer, add to the array.
  for (let i = 0; i <= max; i++) {
    if (i >= min) plaintexts.push(Plaintext.fromBigInteger(last_plaintext));

    last_plaintext = last_plaintext.multiply(pk.g).mod(pk.p);
  }

  return plaintexts;
}
