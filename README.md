# `@shgysk8zer0/aes-gcm`

A JWK-base crypto library using AES-GCM secret keys

[![CodeQL](https://github.com/shgysk8zer0/aes-gcm/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/shgysk8zer0/aes-gcm/actions/workflows/codeql-analysis.yml)
![Node CI](https://github.com/shgysk8zer0/aes-gcm/workflows/Node%20CI/badge.svg)
![Lint Code Base](https://github.com/shgysk8zer0/aes-gcm/workflows/Lint%20Code%20Base/badge.svg)

[![GitHub license](https://img.shields.io/github/license/shgysk8zer0/aes-gcm.svg)](https://github.com/shgysk8zer0/aes-gcm/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/shgysk8zer0/aes-gcm.svg)](https://github.com/shgysk8zer0/aes-gcm/commits/master)
[![GitHub release](https://img.shields.io/github/release/shgysk8zer0/aes-gcm?logo=github)](https://github.com/shgysk8zer0/aes-gcm/releases)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/shgysk8zer0?logo=github)](https://github.com/sponsors/shgysk8zer0)

[![npm](https://img.shields.io/npm/v/@shgysk8zer0/aes-gcm)](https://www.npmjs.com/package/@shgysk8zer0/aes-gcm)
![node-current](https://img.shields.io/node/v/@shgysk8zer0/aes-gcm)
![npm bundle size gzipped](https://img.shields.io/bundlephobia/minzip/@shgysk8zer0/aes-gcm)
[![npm](https://img.shields.io/npm/dw/@shgysk8zer0/aes-gcm?logo=npm)](https://www.npmjs.com/package/@shgysk8zer0/aes-gcm)

[![GitHub followers](https://img.shields.io/github/followers/shgysk8zer0.svg?style=social)](https://github.com/shgysk8zer0)
![GitHub forks](https://img.shields.io/github/forks/shgysk8zer0/aes-gcm.svg?style=social)
![GitHub stars](https://img.shields.io/github/stars/shgysk8zer0/aes-gcm.svg?style=social)
[![Twitter Follow](https://img.shields.io/twitter/follow/shgysk8zer0.svg?style=social)](https://twitter.com/shgysk8zer0)

[![Donate using Liberapay](https://img.shields.io/liberapay/receives/shgysk8zer0.svg?logo=liberapay)](https://liberapay.com/shgysk8zer0/donate "Donate using Liberapay")
- - -

- [Code of Conduct](./.github/CODE_OF_CONDUCT.md)
- [Contributing](./.github/CONTRIBUTING.md)
<!-- - [Security Policy](./.github/SECURITY.md) -->

## Description

A JWK-based crypto library using AES-GCM secret keys. This library provides a set of functions for generating, encrypting, decrypting, signing, and verifying cryptographic keys and data. It supports various cryptographic algorithms and formats, making it easy to handle secure data operations in JavaScript.

## Installation

### Using npm

```sh
npm install @shgysk8zer0/aes-gcm
```

### Using unpkg.com

```html
<script type="importmap">
{
  "imports": {
    "@shgysk8zer0/aes-gcm": "https://unpkg.com/@shgysk8zer0/aes-gcm?module"
  }
}
</script>
<script type="module">
  import { generateSecretKey } from '@shgysk8zer0/aes-gcm';

  const key = await generateSecretKey();
  console.log(key);
</script>
```

## Usage Examples

### Generating a Secret Key

```javascript
import { generateSecretKey } from '@shgysk8zer0/aes-gcm';

const key = await generateSecretKey();
console.log(key);
```
[Documentation for `generateSecretKey`](#generate-secret-key)

### Encrypting and Decrypting Data

```javascript
import { encrypt, decrypt, TEXT } from '@shgysk8zer0/aes-gcm';

const key = await generateSecretKey();
const data = 'Hello, World!';
const encrypted = await encrypt(key, data);
const decrypted = await decrypt(key, encrypted, { output: TEXT });

console.log(decrypted); // 'Hello, World!'
```
[Documentation for `encrypt`](#encrypt-data) and [Documentation for `decrypt`](#decrypt-data)

### Encrypting and Decrypting Files

```javascript
import { encryptFile, decryptFile } from '@shgysk8zer0/aes-gcm';

const key = await generateSecretKey();
const file = new File(['Hello, World!'], 'hello.txt', { type: 'text/plain' });
const encryptedFile = await encryptFile(key, file);
const decryptedFile = await decryptFile(key, encryptedFile);

console.log(await decryptedFile.text()); // 'Hello, World!'
```
[Documentation for `encryptFile`](#encrypt-file) and [Documentation for `decryptFile`](#decrypt-file)

### Creating a Secret Key from a Password

```javascript
import { createSecretKeyFromPassword } from '@shgysk8zer0/aes-gcm';

const password = 'super-secret-password';
const key = await createSecretKeyFromPassword(password);
console.log(key);
```
[Documentation for `createSecretKeyFromPassword`](#create-secret-key-from-password)

### Hashing Data

```javascript
import { hash, HEX } from '@shgysk8zer0/aes-gcm';

const data = 'Hello, World!';
const hashed = await hash(data, { output: HEX });

console.log(hashed);
```
[Documentation for `hash`](#hash-data)

### Signing and Verifying Data

```javascript
import { sign, verifySignature } from '@shgysk8zer0/aes-gcm';

const key = await generateSecretKey();
const data = 'Hello, World!';
const signature = await sign(key, data);
const isValid = await verifySignature(key, data, signature);

console.log(isValid); // true
```
[Documentation for `sign`](#sign-data) and [Documentation for `verifySignature`](#verify-signature)

## API Documentation

### Methods

| Method | Description | Example |
|--------|-------------|---------|
| `generateSecretKey(options)` | Generates a new secret key. | `const key = await generateSecretKey();` |
| `encrypt(key, thing, options)` | Encrypts data using a provided CryptoKey. | `const encrypted = await encrypt(key, data);` |
| `decrypt(key, thing, options)` | Decrypts data using a provided CryptoKey. | `const decrypted = await decrypt(key, encrypted);` |
| `encryptFile(key, file, name)` | Encrypts a file using a provided CryptoKey. | `const encryptedFile = await encryptFile(key, file);` |
| `decryptFile(key, file)` | Decrypts a file using a provided CryptoKey. | `const decryptedFile = await decryptFile(key, encryptedFile);` |
| `createSecretKeyFromPassword(pass, options)` | Creates a secret key from a password. | `const key = await createSecretKeyFromPassword(password);` |
| `hash(thing, options)` | Hashes data using a specified algorithm. | `const hashed = await hash(data);` |
| `sign(key, thing, options)` | Signs data using a provided CryptoKey. | `const signature = await sign(key, data);` |
| `verifySignature(key, source, signature, options)` | Verifies the signature of a given data using a provided CryptoKey. | `const isValid = await verifySignature(key, data, signature);` |

### Options

#### Generate Secret Key

`generateSecretKey(options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | `string` | `'AES-GCM'` | The name of the algorithm. |
| `length` | `number` | `256` | The desired key length in bits. |
| `extractable` | `boolean` | `true` | Whether the key should be extractable. |
| `usages` | `string[]` | `['encrypt', 'decrypt']` | Usages for the key. |

#### Encrypt Data

`encrypt(key, thing, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `iv` | `Uint8Array` | `undefined` | Initialization vector (IV) used for encryption. |
| `output` | `string` | `'ui8'` | Output format for the encrypted data. |

#### Decrypt Data

`decrypt(key, thing, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `input` | `string` | `'base64'` | Input format of the encrypted data when `thing` is a string. |
| `output` | `string` | `'buffer'` | Output format for the decrypted data. |

#### Create Secret Key from Password

`createSecretKeyFromPassword(pass, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | `string` | `'AES-GCM'` | The name of the key algorithm. |
| `length` | `number` | `256` | The desired key length in bits. |
| `hash` | `string` | `'SHA-256'` | The hash algorithm to use for PBKDF2. |
| `iterations` | `number` | `100000` | The number of iterations for PBKDF2. |
| `extractable` | `boolean` | `false` | Whether the key can be extracted. |
| `usages` | `string[]` | `['encrypt', 'decrypt']` | The intended usages for the key. |

#### Hash Data

`hash(thing, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algo` | `string` | `'SHA-256'` | The hashing algorithm to use. |
| `output` | `string` | `'buffer'` | The output format for the hash. |

#### Sign Data

`sign(key, thing, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algo` | `string` | `'SHA-256'` | The hashing algorithm to use. |
| `iv` | `Uint8Array` | `undefined` | Initialization vector (IV) used for encryption. |
| `output` | `string` | `'ui8'` | Output format for the signed data. |

#### Verify Signature

`verifySignature(key, source, signature, options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algo` | `string` | `'SHA-256'` | The hashing algorithm used for signing. |
| `input` | `string` | `'hex'` | The input format of the signature if it's a string. |
