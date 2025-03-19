import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import {
  CryptoSystem,
  type CryptoSystemJSON,
  Plaintext,
} from "../src/index.ts";

const CRYPTO_PARAMS: CryptoSystemJSON = {
  p: "16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071",
  g: "14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533",
  q: "61329566248342901292543872769978950870633559608669337131139375508370458778917",
};

Deno.test("Elgamal::demo", async () => {
  const message = "Hello, World!";
  // const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);
  const system = await CryptoSystem.generateSecureParams(512);
  const keyPair = await system.generateKeyPair();

  console.log(keyPair);

  const plaintext = await Plaintext.fromString(message);
  const encrypted = await keyPair.pk.encrypt(plaintext);

  const decrypted = keyPair.sk.decrypt(encrypted);
  assertEquals(await decrypted.compareToString(message), true);
  assertEquals(plaintext.toString(), decrypted.toString());
});
