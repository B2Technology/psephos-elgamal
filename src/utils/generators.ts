import type { BigInteger } from "./big-Integer.ts";
import type { Commitment } from "../commitment.ts";
import { sha1ToBigInt } from "./helpers.ts";

export type FiatShamirChallengeGeneratorFn = (
  commitment: Commitment,
) => Promise<BigInteger>;

export type DLogChallengeGeneratorFn = (
  commitment: BigInteger,
) => Promise<BigInteger>;

export type DisjunctiveChallengeGeneratorFn = (
  commitments: Commitment[],
) => Promise<BigInteger>;

export const disjunctiveChallengeGenerator: DisjunctiveChallengeGeneratorFn = (
  commitments: Commitment[],
): Promise<BigInteger> => {
  const arrayToHash: string[] = [];
  for (const commitment of commitments) {
    arrayToHash.push(String(commitment.A));
    arrayToHash.push(String(commitment.B));
  }

  const stringToHash = arrayToHash.join(",");
  return sha1ToBigInt(stringToHash);
};

export const fiatShamirChallengeGenerator: FiatShamirChallengeGeneratorFn = (
  commitment: Commitment,
): Promise<BigInteger> => {
  return disjunctiveChallengeGenerator([commitment]);
};

export const dLogChallengeGenerator: DLogChallengeGeneratorFn = (
  commitment: BigInteger,
): Promise<BigInteger> => sha1ToBigInt(commitment.toString());
