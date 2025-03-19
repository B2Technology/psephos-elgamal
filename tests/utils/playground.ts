import { BigInteger } from "npm:jsbn@1.1.0";

const a = new BigInteger(
  "2988348162058574136915891421498819466320163312926952423791023078876139",
);
const b = new BigInteger(
  "2351399303373464486466122544523690094744975233415544072992656881240319",
);
const c = new BigInteger("1527229998585248450016808958343740453059");

const r = a.modPow(b, c);

console.log(
  r.toString(),
  r.toString() === "1527229998585248450016808958343740453059",
);
