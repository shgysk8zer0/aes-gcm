import '@shgysk8zer0/polyfills';
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { readFile } from 'node:fs/promises';
import { setMaxListeners } from 'node:events';
import {
	generateSecretKey, encrypt, decrypt, sign, verifySignature, hash, verify, getSecretKey, HEX, TEXT, BASE64, SHA512,
	createSecretKeyFromPassword, encryptFile, decryptFile, wrapKey, generateWrappingKey,
	unwrapKey, createWrappingKeyFromPassword, WRAP_USAGES, ENCRYPT_USAGES,
} from '@shgysk8zer0/aes-gcm';

describe('Test encryption and decryption', async () => {
	const signal = AbortSignal.timeout(3000);
	const key = await generateSecretKey();
	const input = 'Hello, World!';
	const inputHash = '374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387';

	// Disable complaining about events on `signal`
	setMaxListeners(15, signal);

	test('Secret keys should be able to be import from `process.env`', { signal }, async () => {
		const key = await getSecretKey();

		assert.ok(key instanceof CryptoKey, 'Should be able to import keys from environment variables.');
		assert.deepStrictEqual(key.usages, ENCRYPT_USAGES, 'Generated secret key should have encrpytion usages.');
	});

	test('Check password-based encryption & decryption', { signal }, async () => {
		const key = await createSecretKeyFromPassword(crypto.randomUUID());
		const encrypted = await encrypt(key, input);
		const decrypted = await decrypt(key, encrypted, { output: TEXT });

		assert.ok(encrypted instanceof Uint8Array, 'Password encrypted content should default to an Uint8Arrray.');
		assert.strictEqual(input, decrypted, 'Password-based decrpyption should return initial input.');
		assert.rejects(decrypt(await createSecretKeyFromPassword('invalid-pass'), encrypted), 'Invalid password should throw/reject when decrypting.');
	});

	test('Successfully generate secret keys', { signal }, async () => {
		const key = await generateSecretKey();
		assert.ok(key instanceof CryptoKey, '`generateSecretKey() should return `Promise<CryptoKey>`.');
		assert.rejects(() => generateSecretKey({ length: 1 }), 'Generating keys of invalid length should throw/reject.');
	});

	test('Unwraped keys should decrypt data encrypted by the original.', { signal }, async () => {
		const kek = await generateWrappingKey();
		assert.ok(kek instanceof CryptoKey, 'Generated key should be a `CryptoKey`');
		assert.deepEqual(kek.usages, WRAP_USAGES, 'Wrapping key should have wrapping usages.');

		const wrapped = await wrapKey(kek, key);
		const unwrapped = await unwrapKey(kek, wrapped);
		assert.ok(unwrapped instanceof CryptoKey, 'Unwrapped key should be a `CryptoKey`');
		assert.deepStrictEqual(unwrapped.usages, key.usages, 'Unwrapped key should have the same key usages.');
		assert.deepStrictEqual(unwrapped.algorithm, key.algorithm, 'Unwrapped key should have the same key usages.');

		const encrypted = await encrypt(key, input);
		const decrypted = await decrypt(unwrapped, encrypted, { output: TEXT });
		assert.strictEqual(decrypted, input, 'Unwrapped key should decrypt data correctly.');
	});

	test('Create wrapping key from password.', { signal }, async () => {
		const kek = await createWrappingKeyFromPassword('Super secret password');

		assert.ok(kek instanceof CryptoKey, 'Generated key should be a `CryptoKey`');
		assert.deepStrictEqual(kek.usages, WRAP_USAGES, 'Wrapping key should have wrapping usages.');
	});

	test('Decryption yields the same as what was encrypted', { signal }, async () => {
		const encrypted = await encrypt(key, input);
		const decrypted = await decrypt(key, encrypted, { output: TEXT});

		assert.strictEqual(decrypted, input, 'Decrypted results should be the same as input.');
		assert.rejects(() => encrypt(key, { foo: 'bar' }), 'Encrypting invalid types should throw/reject.');
		assert.rejects(async () => decrypt(await generateSecretKey(), encrypted), 'Decrpyting with wrong key should throw/reject.');
		assert.rejects(() => decrypt(key, crypto.getRandomValues(new Uint8Array(32))), 'Decrpyting invalid data should throw/reject.');
		assert.rejects(() => decrypt(key, { foo: 'bar' }), 'Decrypting invalid types should throw/reject.');
	});

	test('Check file encryption & decryption', { signal }, async () => {
		const file = new File([input], 'hi.txt', { type: 'text/plain' });
		const encrypted = await encryptFile(key, file);
		const decrypted = await decryptFile(key, encrypted);

		assert.ok(encrypted instanceof File, 'encryptFile should resolve with a file.');
		assert.ok(decrypted instanceof File, 'decryptFile should resolve with a file.');
		assert.strictEqual(file.name, decrypted.name, 'Decrypted file should have the same filename');
		assert.strictEqual(file.type, decrypted.type, 'Decrypted file should have the same mime-type');
		assert.strictEqual(file.size, decrypted.size, 'Decrypted file should have the same size');
		assert.strictEqual(file.lastModified, decrypted.lastModified, 'Decrypted file should have the same last modification date.');
		assert.strictEqual(input, await decrypted.text(), 'File should decrpyt to have the exact same content.');
	});

	test('Check encryption of large files', { signal }, async () => {
		const buffer = await readFile('package-lock.json');
		const file = new File([buffer], 'package-lock.json', { type: 'application/json' });
		assert.doesNotReject(encryptFile(key, file));
	});

	test('Encryption works with encoded strings', ({ signal }), async () => {
		const encrypted = await encrypt(key, input, { output: BASE64 });
		const decrypted = await decrypt(key, encrypted, { input: BASE64, output: TEXT });

		assert.strictEqual(decrypted, input, 'Text encryption/decryption should work with strings and base64 encoding.');
	});

	test('Basic hashing tests (SHA-512)', { signal }, async () => {
		const hashed = await hash(input, { algo: SHA512, output: HEX });

		assert.strictEqual(hashed, inputHash, 'Should generate expected hash');
		assert.ok(await verify(input, inputHash, { input: HEX, algo: SHA512 }), 'Hash verification should pass.');
		assert.ok(! await verify(input + 'x', inputHash, { input: HEX, algo: SHA512 }), 'Different hashes should not verify.');
	});

	test('Verify encrypted signatures', { signal }, async () => {
		const signature = await sign(key, input);

		assert.ok(await verifySignature(key, input, signature), 'Signature should match.');
	});

	test('Verify encrypted signatures (text version)', { signal }, async () => {
		const signature = await sign(key, input, { output: HEX });

		assert.ok(await verifySignature(key, input, signature, { input: HEX }), 'Signature should match via text.');
	});
});
