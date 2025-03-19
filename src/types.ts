import type { BigInteger } from "./utils/index.ts";
import type { Commitment } from "./commitment.ts";

export type ChallengeGeneratorByCommitFn = (
  commitment: Commitment,
) => Promise<BigInteger>;

export type ChallengeGeneratorByBigIntFn = (
  commitment: BigInteger,
) => Promise<BigInteger>;
