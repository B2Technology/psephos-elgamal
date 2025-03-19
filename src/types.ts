import type { BigInteger } from "./utils/big-Integer.ts";
import type { Commitment } from "./commitment.ts";

export type ChallengeGeneratorFn = (commitment: Commitment) => BigInteger;
