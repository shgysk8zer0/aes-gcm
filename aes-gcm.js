const decoder = new TextDecoder();
const encoder = new TextEncoder();

// Cryptographic Algorithm constants
export const IV_LENGTH = 12;
export const AES_CTR = 'AES-CTR';
export const AES_GCM = 'AES-GCM';
export const AES_CBC = 'AES-CBC';
export const DEFAULT_ALGO_NAME = AES_GCM;
export const DEFAULT_LENGTH = 256;
export const KEY_OPS = ['encrypt', 'decrypt'];

// Hashing Algorithms
export const SHA256 = 'SHA-256';
export const SHA384 = 'SHA-384';
export const SHA512 = 'SHA-512';
export const DEFAULT_ALGO = SHA256;

// I/O Formats
export const BUFFER = 'buffer';
export const BASE64 = 'base64';
export const BASE64_URL = 'base64url';
export const UI8_ARR = 'ui8';
export const HEX = 'hex';
export const TEXT = 'text';
export const DEFAULT_OUTPUT = UI8_ARR;

// File-related constants
export const FILE_EXT = '.aes-enc';
export const FILE_TYPE_PREFIX = 'application/aes-encrypted+';

/**
 * Constant-time comparison of two ArrayBuffers
 *
 * @param {ArrayBuffer} a - First buffer to compare
 * @param {ArrayBuffer} b - Second buffer to compare
 * @returns {boolean} - Whether the buffers are equal
 */
function _safeBufferCompare(a, b) {
	// Convert to Uint8Array for comparison
	const bufA = new Uint8Array(a);
	const bufB = new Uint8Array(b);

	// Ensure we always compare the full lengths
	const maxLength = Math.max(bufA.length, bufB.length);
	let diff = bufA.length !== bufB.length ? 1 : 0;

	// Compare bytes, padding shorter buffer with zeros
	for (let i = 0; i < maxLength; i++) {
		// Use 0 for out-of-bounds indices
		const byteA = i < bufA.length ? bufA[i] : 0;
		const byteB = i < bufB.length ? bufB[i] : 0;

		// Accumulate differences
		diff |= byteA ^ byteB;
	}

	// The result will be 0 only if all bytes are identical
	return diff === 0;
}

/**
 * Generates a new AES-GCM secret key.
 *
 * @param {object} options
 * @param {number} [options.length=256] The desired key length in bits.
 * @param {boolean} [options.extractable=true] Whether the key should be extractable for use outside the current context.
 * @returns {Promise<CryptoKey>} The newly generated secret key.
 */
export async function generateSecretKey({
	length = DEFAULT_LENGTH,
	extractable = true,
} = {}) {
	return await crypto.subtle.generateKey({ name: AES_GCM, length, }, extractable, KEY_OPS);
}

/**
 * Creates an ephemeral CryptoKey from a given password using the AES-GCM algorithm.
 *
 * @param {string} pass The password to use for key derivation.
 * @param {object} options
 * @param {number} [options.length=256] The desired key length in bits.
 * @param {boolean} [options.extractable=false] Whether the key should be extractable from the WebCrypto API.
 * @returns {Promise<CryptoKey>} The generated `CryptoKey`.
 * @throws {TypeError} Thrown if password is not a string, is an empty string, or if the config to generate the key is invalid.
 */
export async function createSecretKeyFromPassword(pass, {
	length = DEFAULT_LENGTH,
	extractable = false,
} = {}) {
	if (typeof pass !== 'string' || pass.length === 0) {
		throw new TypeError('Key password must be a non-empty string.');
	} else {
		const hash = await crypto.subtle.digest(SHA256, encoder.encode(pass));
		return await crypto.subtle.importKey('raw', hash, { name: AES_GCM, length }, extractable, KEY_OPS);
	}
}

/**
 * Retrieves a secret key from the environment variable.
 *
 * @param {string} [prop='SECRET_KEY'] The environment variable name.
 * @returns {Promise<CryptoKey>} The imported secret key.
 */
export async function getSecretKey(prop = 'SECRET_KEY') {
	const [name, data] = process.env[prop].split(':');
	const bytes = Uint8Array.fromBase64(data);
	const keyData = JSON.parse(decoder.decode(bytes));

	return await crypto.subtle.importKey('jwk', keyData, { name }, keyData.ext, keyData.key_ops);
}

/**
 * Encrypts data using a provided CryptoKey.
 *
 * @param {CryptoKey} key - The CryptoKey used for encryption. Must allow encryption (`usages` includes 'encrypt').
 * @param {string|Blob|ArrayBuffer|ArrayBufferView} thing - The data to be encrypted.
 * @param {object} options - Optional configuration for encryption.
 * @param {Uint8Array} [options.iv=crypto.getRandomValues(new Uint8Array(12))] - Initialization vector (IV) used for encryption. Defaults to a random 12-byte Uint8Array.
 * @param {string} [options.output='ui8'] -  Output format for the encrypted data.
 * @returns {Promise<Uint8Array|string>} - The encrypted data. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the key is invalid, IV is invalid, or the data type is not supported for encryption.
 */
export async function encrypt(key, thing, {
	iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH)),
	output = DEFAULT_OUTPUT,
} = {}) {
	if (! (key instanceof CryptoKey) || ! key.usages.includes('encrypt')) {
		throw new TypeError('Invalid key.');
	} else if (! (iv instanceof Uint8Array)) {
		throw new TypeError('Invalid IV.');
	} else if (typeof thing === 'string') {
		return await encrypt(key, encoder.encode(thing), { iv, output });
	} else if (thing instanceof Blob) {
		return await encrypt(key, await thing.arrayBuffer(), { iv, output });
	} else if (thing instanceof ArrayBuffer || ArrayBuffer.isView(thing)) {
		const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: key.algorithm.name, iv }, key, thing));
		const bytes = new Uint8Array(iv.length + encrypted.length);
		bytes.set(iv, 0);
		bytes.set(encrypted, iv.length);

		switch(output) {
			case BUFFER:
				return bytes.buffer;

			case UI8_ARR:
				return bytes;

			case HEX:
				return bytes.toHex();

			case BASE64:
				return bytes.toBase64({ alphabet: BASE64 });

			case BASE64_URL:
				return bytes.toBase64({ alphabet: BASE64_URL });

			case TEXT:
				return decoder.decode(bytes);

			default:
				throw new TypeError(`Invalid output: ${output}.`);
		}
	} else {
		throw new TypeError('Unsupported type/class to encrypt.');
	}
}

/**
 * Decrypts data using a provided CryptoKey.
 *
 * @param {CryptoKey} key - The CryptoKey used for decryption. Must allow decryption (`usages` includes 'decrypt').
 * @param {string|Blob|ArrayBuffer|ArrayBufferView} thing - The data to be decrypted.
 * @param {object} options - Optional configuration for decryption.
 * @param {string} [options.input='base64'] - Input format of the encrypted data when `thing` is a string.
 * @param {string} [options.output='buffer'] - Output format for the decrypted data.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The decrypted data. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the key is invalid, the input format is unsupported, or the output format is invalid.
 */
export async function decrypt(key, thing, {
	input = BASE64,
	output = BUFFER,
} = {}) {
	if (! (key instanceof CryptoKey) || ! key.usages.includes('decrypt')) {
		throw new TypeError('Invalid key.');
	} else if (typeof thing === 'string') {
		switch (input) {
			case HEX:
				return await decrypt(key, Uint8Array.fromHex(thing), { output });

			case BASE64:
				return await decrypt(key, Uint8Array.fromBase64(thing, { alphabet: BASE64 }), { output });

			case BASE64_URL:
				return await decrypt(key, Uint8Array.fromBase64(thing, { alphabet: BASE64_URL }), { output });

			case TEXT:
				return await decrypt(key, encoder.encode(thing), { output });

			default:
				throw new TypeError(`Unspupported input format: ${input}.`);
		}
	} else if (thing instanceof Blob) {
		return await decrypt(key, await thing.arrayBuffer(), { output });
	} else if (thing instanceof ArrayBuffer || ArrayBuffer.isView(thing)) {
		const iv = thing.slice(0, 12);
		const payload = thing.slice(12);
		const result = await crypto.subtle.decrypt({ name: key.algorithm.name, iv }, key, payload);

		switch(output) {
			case BUFFER:
				return result;

			case UI8_ARR:
				return new Uint8Array(result);

			case BASE64:
				return new Uint8Array(result).toBase64({ alphabet: BASE64 });

			case BASE64_URL:
				return new Uint8Array(result).toBase64({ alphabet: BASE64_URL });

			case TEXT:
				return decoder.decode(result);

			default:
				throw new TypeError(`Invalid output type: ${output}.`);
		}
	} else {
		throw new TypeError('Unsupported type/class to decrypt.');
	}
}

/**
 * Hashes data using a specified algorithm.
 *
 * @param {string|Blob|ArrayBuffer|ArrayBufferView} thing - The data to be hashed.
 * @param {object} options - Optional configuration for hashing.
 * @param {string} [options.algo='SHA-256'] - The hashing algorithm to use.
 * @param {string} [options.output='buffer'] - The output format for the hash.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The hash. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the data type is not supported for hashing or the output format is invalid.
 */
export async function hash(thing, {
	algo = DEFAULT_ALGO,
	output = BUFFER,
} = {}) {
	if (typeof thing === 'string') {
		return await hash(encoder.encode(thing), { algo, output });
	} else if (thing instanceof Blob) {
		return await hash(await thing.arrayBuffer(), { algo, output });
	} else if (thing instanceof ArrayBuffer || ArrayBuffer.isView(thing)) {
		const result = await crypto.subtle.digest(algo, thing);

		switch(output) {
			case BUFFER:
				return result;

			case UI8_ARR:
				return new Uint8Array(result);

			case HEX:
				return new Uint8Array(result).toHex();

			case BASE64:
				return new Uint8Array(result).toBase64({ alphabet: BASE64 });

			case BASE64_URL:
				return new Uint8Array(result).toBase64({ alphabet: BASE64_URL });

			case TEXT:
				return decoder.decode(result);

			default:
				throw new TypeError(`Invalid output: ${output}.`);
		}

	} else {
		throw new TypeError('Unsupported type/class to hash.');
	}
}

/**
 * Signs data using a provided CryptoKey.
 *
 * @param {CryptoKey} key - The CryptoKey used for signing. Must allow encryption (`usages` includes 'encrypt').
 * @param {string|Blob|ArrayBuffer|ArrayBufferView} thing - The data to be signed.
 * @param {object} options - Optional configuration for signing.
 * @param {string} [options.algo='SHA-256'] - The hashing algorithm to use.
 * @param {Uint8Array} [options.iv=crypto.getRandomValues(new Uint8Array(12))] - Initialization vector (IV) used for encryption. Defaults to a random 12-byte Uint8Array.
 * @param {string} [options.output='ui8'] - Output format for the signed data.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The signature for data. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the key is invalid, the hashing algorithm is unsupported, or the output format is invalid.
 */
export async function sign(key, thing, {
	algo = DEFAULT_ALGO,
	iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH)),
	output = DEFAULT_OUTPUT,
} = {}) {
	const hashed = await hash(thing, { algo, output: BUFFER });
	return await encrypt(key, hashed, { iv, output });
}

/**
 * Verifies the hash of a given data against an expected hash.

 * @param {string|Blob|ArrayBuffer|ArrayBufferView} thing - The data to be hashed and compared.
 * @param {ArrayBuffer|Uint8Array} expected - The expected hash.
 * @param {object} options - Optional configuration for verification.
 * @param {string} [options.algo='SHA-256'] - The hashing algorithm to use.
 * @param {string} [options.input='hex'] - The input format of the expected hash if it's a string.
 * @returns {Promise<boolean>} - `true` if the hashes match, `false` otherwise.
 * @throws {TypeError} - Thrown if the input format of the expected hash is invalid.
 */
export async function verify(thing, expected, {
	algo = DEFAULT_ALGO,
	input = HEX,
} = {}) {
	if (typeof expected === 'string') {
		switch(input) {
			case HEX:
				return await verify(thing, Uint8Array.fromHex(expected).buffer, { algo });

			case BASE64:
				return await verify(thing, Uint8Array.fromBase64(expected, { alphabet: BASE64 }).buffer, { algo });

			case BASE64_URL:
				return await verify(thing, Uint8Array.fromBase64(expected, { alphabet: BASE64_URL }).buffer, { algo });

			case TEXT:
				return await verify(thing, encoder.encode(expected).buffer, { algo });

			default:
				throw new TypeError(`Invalid input type: ${input}.`);
		}
	} else if (expected instanceof Uint8Array) {
		return await verify(thing, expected.buffer, { algo });
	} else {
		const hashed = await hash(thing, { algo, output: BUFFER });
		return _safeBufferCompare(hashed, expected);
	}
}

/**
 * Verifies the signature of a given data using a provided CryptoKey.

 * @param {CryptoKey} key - The CryptoKey used for verification. Must allow decryption (`usages` includes 'decrypt').
 * @param {string|Blob|ArrayBuffer|ArrayBufferView} source - The original data.
 * @param {ArrayBuffer|Uint8Array|string} signature - The signature to verify.
 * @param {object} options - Optional configuration for verification.
 * @param {string} [options.algo='SHA-256'] - The hashing algorithm used for signing.
 * @param {string} [options.input='hex'] - The input format of the signature if it's a string.
 * @returns {Promise<boolean>} - `true` if the signature is valid, `false` otherwise.
 * @throws {TypeError} - Thrown if the key is invalid, the input format of the signature is invalid, or the decryption fails.
 */
export async function verifySignature(key, source, signature, {
	algo = DEFAULT_ALGO,
	input = HEX,
} = {}) {
	const expected = await decrypt(key, signature, { output: BUFFER, input });
	return await verify(source, expected, { algo, input: BUFFER });
}

/**
 * Encrypts a file and wraps it in a custom file extension and MIME type.
 *
 * @param {CryptoKey} key A cryptographic key for encryption.
 * @param {File} file The file to encrypt.
 * @returns {Promise<File>} A new File instance with encrypted content.
 * @throws {TypeError} If `file` is not a valid File object or `key` is not a valid `CryptoKey`
 */
export async function encryptFile(key, file) {
	if (! (file instanceof File)) {
		throw new TypeError('encryptFile requires a File object.');
	} else {
		const content = await encrypt(key, await file.arrayBuffer(), { output: BUFFER });

		return new File([content], `${file.name}${FILE_EXT}`, {
			type: `${FILE_TYPE_PREFIX}${file.type}`,
			lastModified: file.lastModified,
		});
	}
}

/**
 * Decrypts a file encrypted by `encryptFile`.
 *
 * @param {CryptoKey} key A cryptographic key for decryption.
 * @param {File} file The file to decrypt.
 * @return {Promise<File>} A new File instance with decrypted content, having name and metadata of the original.
 * @throws {TypeError} If `file` is not a valid File object or `key` is not a valid `CryptoKey`
 */
export async function decryptFile(key, file) {
	if (! (file instanceof File)) {
		throw new TypeError('decryptFile requires a File object.');
	} else {
		const decrypted = await decrypt(key, await file.arrayBuffer(), { output: BUFFER });

		return new File([decrypted], file.name.replace(FILE_EXT, ''), {
			type: file.type.replace(FILE_TYPE_PREFIX, ''),
			lastModified: file.lastModified,
		});
	}
}
