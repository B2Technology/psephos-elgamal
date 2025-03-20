# Psephos - Elgamal

Uma implementação TypeScript moderna do sistema de criptografia ElGamal,
otimizada para Deno, NodeJS e web. Com foco em aplicações de votação eletrônica
e protocolos de conhecimento zero.

## Características

- Implementação completa do sistema de criptografia ElGamal
- Provas de conhecimento zero para verificar integridade
- Operações homomórficas para aplicações de contagem
- Suporte para Deno e ambientes modernos de JavaScript/TypeScript
- API bem estruturada com tipagem forte
- Implementação eficiente baseada em BigInteger nativo

## Instalação

A biblioteca possui suporte para ES Modules, CommonJS e Deno. Para instalar:

```bash
# Para Deno (instalação via import_map.json)
deno add jsr:@psephos/elgamal

# Para Deno (importação direta)
import { CryptoSystem, Plaintext } from "jsr:@psephos/elgamal@1.0.5";

# Para NPM
npm install @psephos/elgamal

# Para YARN
yarn add @psephos/elgamal
```

## Uso Básico

```typescript
import {CryptoSystem, Plaintext} from "@psephos/elgamal";
import {
    BigInteger,
    disjunctiveChallengeGenerator,
} from "@psephos/elgamal/utils";

// Criação de um sistema criptográfico
const system = await CryptoSystem.generateSecureParams(2048);

// Geração de par de chaves
const keyPair = await system.generateKeyPair();

// Encriptação
const mensagem = await Plaintext.fromString("Mensagem secreta");
const ciphertext = await keyPair.pk.encrypt(mensagem);

// Decriptação
const mensagemDecriptada = keyPair.sk.decrypt(ciphertext);
const verificacao = await mensagemDecriptada.compareToString(
    "Mensagem secreta",
);
console.log("Mensagem verificada:", verificacao); // true
```

## Funcionalidades Principais

### Criptografia ElGamal

Encriptação com randomness específico

```typescript
const plaintext = Plaintext.fromBigInteger(new BigInteger("12345"));
const r = new BigInteger("54321");
const ciphertext = keyPair.pk.encryptWithR(plaintext, r);
```

### Operações Homomórficas

Multiplicação de ciphertexts (adição de plaintexts)

```typescript
const ciphertext1 = await keyPair.pk.encrypt(plaintext1);
const ciphertext2 = await keyPair.pk.encrypt(plaintext2);
const combinedCiphertext = ciphertext1.multiply(ciphertext2);
```

### Provas de Conhecimento Zero

Prova de conhecimento de chave privada:

```typescript
const proof = await keyPair.sk.proveSk(dLogChallengeGenerator);
const verificado = await keyPair.pk.verifySkProof(
    proof,
    dLogChallengeGenerator,
);
```

Prova de encriptação:

```typescript
const [ciphertext, r] = await keyPair.pk.encryptReturnR(plaintext);
const encProof = await ciphertext.generateEncryptionProof(
    r,
    fiatShamirChallengeGenerator,
);
const verificado = ciphertext.verifyEncryptionProof(plaintext, encProof);
```

Prova disjuntiva (por exemplo, para votação sim/não)

```typescript
const plaintext1 = Plaintext.fromBigInteger("1234567890");
const plaintext2 = Plaintext.fromBigInteger("9876543210");
const plaintext3 = Plaintext.fromBigInteger("1234567890");

const [ciphertext, r] = await keyPair.pk.encryptReturnR(plaintext2);
const plaintexts = [plaintext1, plaintext2, plaintext3];
const realIndex = 1; // representa o index do plaintext2 no array plaintexts
const zkProof = await ciphertext.generateDisjunctiveEncryptionProof(
    plaintexts,
    realIndex,
    r,
    disjunctiveChallengeGenerator,
);
```

Verificação de prova disjuntiva:

```typescript
const verificado = await ciphertext.verifyDisjunctiveEncryptionProof(
    plaintexts,
    zkProof,
    disjunctiveChallengeGenerator,
);
```

## Estrutura de Classes

- **CryptoSystem**: Gerencia os parâmetros do sistema (p, q, g)
- **KeyPair**: Encapsula um par de chaves pública/privada
- **PublicKey**: Chave pública para encriptação
- **SecretKey**: Chave privada para decriptação
- **Plaintext**: Representação de mensagens em texto puro
- **Ciphertext**: Representação de mensagens encriptadas
- **ZKProof**: Prova de conhecimento zero
- **ZKDisjunctiveProof**: Prova disjuntiva para escolha entre opções

## Aplicações

- Votação eletrônica com verificabilidade
- Sistemas de contagem segura (graças às propriedades homomórficas)
- Protocolos de anonimato
- Aplicações com verificação de integridade

## Segurança

Esta biblioteca implementa ElGamal com parâmetros modernos recomendados (2048+bits).

Para gerar os parâmetros de forma segura, utilize o método `generateSecureParams`:

- $p: Um número primo grande (normalmente 2048 bits ou mais nos dias atuais)
- $q: Um número primo que é divisor de p-1
- $g: Um gerador de um subgrupo cíclico de ordem q em Z*p

## References

- [Elgamal Helios Voting](https://github.com/benadida/helios-server/tree/master/helios/crypto)

## Licença

MIT

## Contribuições

Contribuições são bem-vindas! Por favor, abra uma issue ou envie um pull
request.
