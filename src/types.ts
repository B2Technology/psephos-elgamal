import type { BigInteger } from "./utils/index.ts";
import type { Commitment } from "./commitment.ts";

export type ChallengeGeneratorFn = (commitment: Commitment) => BigInteger;
