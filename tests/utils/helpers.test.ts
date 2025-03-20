import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { sha1Fingerprint, sha1, sha1ToBigInt } from "../../src/utils/index.ts";

Deno.test("Helpers::sha1", async () => {
  const input = "hello";
  const expected = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
  const actual = await sha1(input);
  assertEquals(actual, expected);

  assertEquals(await sha1("11"), "17ba0791499db908433b80f37c5fbc89b870084b");
});

Deno.test("Helpers::sha1ToBigInt", async () => {
  const actual1 = await sha1ToBigInt("hello");
  assertEquals(
    actual1.toString(),
    "975987071262755080377722350727279193143145743181",
  );

  const actual2 = await sha1ToBigInt("11");
  assertEquals(
    actual2.toString(),
    "135455385560672318018989914913299166471400720459",
  );
});

Deno.test("Helpers::sha1Fingerprint", async () => {
  const actual1 = await sha1Fingerprint("hello");
  assertEquals(
    actual1,
    "AA:F4:C6:1D:DC:C5:E8:A2:DA:BE:DE:0F:3B:48:2C:D9:AE:A9:43:4D",
  );

  assertEquals(
    actual1.length,
    59,
  );

  const actual2 = await sha1Fingerprint("11");
  assertEquals(
    actual2,
    "17:BA:07:91:49:9D:B9:08:43:3B:80:F3:7C:5F:BC:89:B8:70:08:4B",
  );
});
