import {
  assertEquals,
  assertNotEquals,
} from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { CryptoSystem, KeyPair, PublicKey, SecretKey } from "../src/index.ts";
import { BigInteger } from "../src/utils/index.ts";

// Parâmetros criptográficos para testes
const CRYPTO_PARAMS = {
  p: "16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071",
  g: "14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533",
  q: "61329566248342901292543872769978950870633559608669337131139375508370458778917",
};

// Valor fixo para testes determinísticos
const FIXED_PRIVATE_KEY = "12345678901234567890";
const system = CryptoSystem.fromJSON(CRYPTO_PARAMS);

Deno.test("KeyPair::construtor", async () => {
  const keyPair = await system.generateKeyPair();

  // Verifica se o par de chaves foi criado corretamente
  assertEquals(keyPair.pk instanceof PublicKey, true);
  assertEquals(keyPair.sk instanceof SecretKey, true);

  // Verifica se a chave privada está corretamente relacionada à chave pública
  assertEquals(keyPair.pk.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(keyPair.pk.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(keyPair.pk.g.toString(), CRYPTO_PARAMS.g);

  // Verifica se a chave pública na chave privada é a mesma instância
  assertEquals(keyPair.sk.pk, keyPair.pk);
});

Deno.test("KeyPair::create", async () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);

  // Cria um par de chaves usando o método estático create
  const keyPair = await KeyPair.create(p, q, g);

  // Verifica se o par de chaves foi criado corretamente
  assertEquals(keyPair.pk instanceof PublicKey, true);
  assertEquals(keyPair.sk instanceof SecretKey, true);

  // Verifica se os parâmetros foram corretamente atribuídos
  assertEquals(keyPair.pk.p.toString(), CRYPTO_PARAMS.p);
  assertEquals(keyPair.pk.q.toString(), CRYPTO_PARAMS.q);
  assertEquals(keyPair.pk.g.toString(), CRYPTO_PARAMS.g);

  // Verifica a relação entre as chaves: g^x mod p = y
  const calculatedY = g.modPow(keyPair.sk.x, p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());
});

Deno.test("KeyPair::createWithPrivateKey", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);
  const sk_x = new BigInteger(FIXED_PRIVATE_KEY);

  // Cria um par de chaves com uma chave privada específica
  const keyPair = KeyPair.createWithPrivateKey(p, q, g, sk_x);

  // Verifica se a chave privada é a especificada
  assertEquals(keyPair.sk.x.toString(), FIXED_PRIVATE_KEY);

  // Verifica a relação entre as chaves: g^x mod p = y
  const calculatedY = g.modPow(sk_x, p);
  assertEquals(calculatedY.toString(), keyPair.pk.y.toString());
});

Deno.test("KeyPair::fromJSON e toJSON", async () => {
  const originalKeyPair = await system.generateKeyPair();

  // Converte para JSON
  const jsonData = originalKeyPair.toJSON();

  // Verifica estrutura JSON
  assertEquals(typeof jsonData.pk, "object");
  assertEquals(typeof jsonData.sk, "object");
  assertEquals(typeof jsonData.pk.p, "string");
  assertEquals(typeof jsonData.pk.q, "string");
  assertEquals(typeof jsonData.pk.g, "string");
  assertEquals(typeof jsonData.pk.y, "string");
  assertEquals(typeof jsonData.sk.x, "string");
  assertEquals(typeof jsonData.sk.publicKey, "object");

  // Recria a partir do JSON
  const recreatedKeyPair = KeyPair.fromJSON(jsonData);

  // Verifica se as chaves foram recriadas corretamente
  assertEquals(
    recreatedKeyPair.pk.p.toString(),
    originalKeyPair.pk.p.toString(),
  );
  assertEquals(
    recreatedKeyPair.pk.q.toString(),
    originalKeyPair.pk.q.toString(),
  );
  assertEquals(
    recreatedKeyPair.pk.g.toString(),
    originalKeyPair.pk.g.toString(),
  );
  assertEquals(
    recreatedKeyPair.pk.y.toString(),
    originalKeyPair.pk.y.toString(),
  );
  assertEquals(
    recreatedKeyPair.sk.x.toString(),
    originalKeyPair.sk.x.toString(),
  );
});

Deno.test("KeyPair::pares de chaves diferentes devem ter chaves privadas diferentes", async () => {
  const [keyPair1, keyPair2] = await Promise.all([
    system.generateKeyPair(),
    system.generateKeyPair(),
  ]);

  // Valores de p, q e g devem ser iguais
  assertEquals(keyPair1.pk.p.toString(), keyPair2.pk.p.toString());
  assertEquals(keyPair1.pk.q.toString(), keyPair2.pk.q.toString());
  assertEquals(keyPair1.pk.g.toString(), keyPair2.pk.g.toString());

  // Chaves privadas devem ser diferentes
  assertNotEquals(keyPair1.sk.x.toString(), keyPair2.sk.x.toString());

  // Chaves públicas também devem ser diferentes
  assertNotEquals(keyPair1.pk.y.toString(), keyPair2.pk.y.toString());
});

Deno.test("KeyPair::mesma chave privada deve gerar mesma chave pública", () => {
  const p = new BigInteger(CRYPTO_PARAMS.p);
  const q = new BigInteger(CRYPTO_PARAMS.q);
  const g = new BigInteger(CRYPTO_PARAMS.g);
  const sk_x = new BigInteger(FIXED_PRIVATE_KEY);

  // Cria dois pares de chaves com a mesma chave privada
  const keyPair1 = KeyPair.createWithPrivateKey(p, q, g, sk_x);
  const keyPair2 = KeyPair.createWithPrivateKey(p, q, g, sk_x);

  // As chaves públicas devem ser iguais
  assertEquals(keyPair1.pk.y.toString(), keyPair2.pk.y.toString());
});
