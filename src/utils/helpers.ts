import * as crypto from "node:crypto";
import type { Commitment } from "../commitment.ts";
import type { ChallengeGeneratorFn } from "../types.ts";
import { BigInteger } from "./big-Integer.ts";

// TODO revisar e testar todos estes metodos

function _randomMpzLt(maximum: bigint): bigint {
  const nBits = Math.floor(Math.log2(Number(maximum))) + 1;
  let res: bigint;

  do {
    res = BigInt(
      `0x${crypto.randomBytes(Math.ceil(nBits / 8)).toString("hex")}`,
    );
  } while (res >= maximum);

  return res;
}

export function randomMpzLt(maximum: BigInteger): BigInteger {
  const _max = BigInt(maximum.toString());
  const _res = _randomMpzLt(_max);

  return new BigInteger(_res.toString());
}

// export function randomMpzLt(maximum: BigInteger): BigInteger {
//   // TODO garantir q esta gerando um randomico seguro
//   const nBits = Math.floor(Math.log2(Number(maximum.toString())));
//
//   let res = new BigInteger(
//     crypto.randomBytes(Math.ceil(nBits / 8)).toString('hex'),
//     16,
//   );
//
//   //(public) return + if this > a, - if this < a, 0 if equal
//   while (res.compareTo(maximum) >= 0) {
//     res = new BigInteger(
//       crypto.randomBytes(Math.ceil(nBits / 8)).toString('hex'),
//       16,
//     );
//   }
//
//   return res;
// }

// TODO ver se a funcaio "utils/textToBigInt" nao faz a mesma coisa (se nao for, mover isso para dentro de utils fora da pasta elgamal)
export function sha1ToBigInt(stringToHash: string): BigInteger {
  const hash = crypto
    .createHash("sha1")
    .update(stringToHash, "utf-8")
    .digest("hex");

  const num = BigInt(`0x${hash}`).toString();

  return new BigInteger(num);
}

export function disjunctiveChallengeGenerator(
  commitments: Commitment[],
): BigInteger {
  const arrayToHash: string[] = [];
  for (const commitment of commitments) {
    arrayToHash.push(String(commitment.A));
    arrayToHash.push(String(commitment.B));
  }

  const stringToHash = arrayToHash.join(",");
  return sha1ToBigInt(stringToHash);
}

export const fiatshamirChallengeGenerator: ChallengeGeneratorFn = (
  commitment: Commitment,
): BigInteger => {
  return disjunctiveChallengeGenerator([commitment]);
};

// TODO analisar e remover caso nao usar
export function DLogChallengeGenerator(commitment: string): BigInteger {
  const stringToHash = String(commitment);
  return sha1ToBigInt(stringToHash);
}
