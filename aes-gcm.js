const decoder = new TextDecoder();
const encoder = new TextEncoder();

// Cryptographic Algorithm constants
export const AES_CTR = 'AES-CTR';
export const AES_GCM = 'AES-GCM';
export const AES_CBC = 'AES-CBC';
export const AES_KW = 'AES-KW';
export const AES_GCM_LENGTH = 12;
export const AES_CBC_LENGTH = 16;
export const DEFAULT_ALGO_NAME = AES_GCM;
export const DEFAULT_IV_LENGTH = AES_GCM_LENGTH;
export const DEFAULT_KEY_LENGTH = 256;
export const DERIVE_KEY = 'deriveKey';
export const DERIVE_BITS = 'deriveBits';
export const ENCRYPT_USAGES = ['encrypt', 'decrypt'];
export const WRAP_USAGES = ['wrapKey', 'unwrapKey'];
export const DERIVE_USAGES = [DERIVE_KEY, DERIVE_BITS];

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
export const FILE_EXT = '.enc';
export const FILE_VERSION = 1;
export const HEADER_SIZE = 128;
export const MAGIC_STR_LEN = 16;
export const IV_HEADER = 'X-ENC-IV';

/**
 * Encode `Uint8Array` bytes into various formats
 *
 * @param {Uint8Array} bytes The bytes as a `Uint8Array`
 * @param {string} encoding The output encoding format
 * @returns {ArrayBuffer|Uint8Array|string} The bytes encoded in the specified way
 */
function _encode(bytes, encoding) {
	if (bytes instanceof ArrayBuffer) {
		return _encode(new Uint8Array(bytes), encoding);
	} else {
		switch(encoding) {
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
				throw new TypeError(`Invalid output: ${encoding}.`);
		}
	}
}

/**
 * Decode a string into a `Uint8Array` with various input formats supported
 *
 * @param {string} str The string to decode.
 * @param {string} encoding The encoding for the string (eg hex, base64)
 * @returns {Uint8Array} The string decoded into a `Uint8Array`
 */
function _decode(str, encoding) {
	switch (encoding) {
		case HEX:
			return Uint8Array.fromHex(str);

		case BASE64:
			return Uint8Array.fromBase64(str, { alphabet: BASE64 });

		case BASE64_URL:
			return Uint8Array.fromBase64(str, { alphabet: BASE64_URL });

		case TEXT:
			return encoder.encode(str);

		default:
			throw new TypeError(`Unspupported input format: ${encoding}.`);
	}
}

/**
 * Constant-time comparison of two ArrayBuffers
 *
 * @param {ArrayBuffer} a - First buffer to compare
 * @param {ArrayBuffer} b - Second buffer to compare
 * @returns {boolean} - Whether the buffers are equal
 */
function _safeBufferCompare(a, b) {
	const bufA = new Uint8Array(a);
	const bufB = new Uint8Array(b);

	const maxLength = Math.max(bufA.length, bufB.length);
	let diff = bufA.length !== bufB.length ? 1 : 0;

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
 * Get the correct IV size for a given key's algorithm
 *
 * @param {CryptoKey} key The key with which to determine algorithm and therefore IV length
 * @returns {number} The appropriate IV length for the key's algorithm
 * @throws {TypeError} If `key` is not a `CryptoKey` or a key with an unsupported algorithm
 */
function _getIVLength(key) {
	if (! (key instanceof CryptoKey)) {
		throw new TypeError('Key must be a `CryptoKey.');
	} else {
		switch(key.algorithm.name) {
			case AES_GCM:
				return AES_GCM_LENGTH;

			case AES_CBC:
				return AES_CBC_LENGTH;

			default:
				throw new TypeError(`Unsupported key algorithm: ${key.algorithm.name}.`);
		}
	}
}

/**
 * Generate a random IV of the correct length for a key type
 *
 * @param {CryptoKey} key
 * @returns {Uint8Array} A random IV (`Uinit8Array`) of the correct length for the alogorithm
 * @throws {TypeError} If `key` is not a `CryptoKey` or a key with an unsupported algorithm
 */
export function generateIV(key) {
	return crypto.getRandomValues(new Uint8Array(_getIVLength(key)));
}

/**
 * Generates a new secret key.
 *
 * @param {object} options
 * @param {string} [options.name='AES-GCM'] The name of the algorithms.
 * @param {number} [options.length=256] The desired key length in bits.
 * @param {boolean} [options.extractable=true] Whether the key should be extractable for use outside the current context.
 * @param {string[]} [options.usages=['encrypt', 'decrypt']] Usages for the key, defaulting to encrpyt and decrypt.
 * @returns {Promise<CryptoKey>} The newly generated secret key.
 */
export async function generateSecretKey({
	name = AES_GCM,
	length = DEFAULT_KEY_LENGTH,
	extractable = true,
	usages = ENCRYPT_USAGES
} = {}) {
	return await crypto.subtle.generateKey({ name, length, }, extractable, usages);
}

/**
 * Generate an AES-KW key for wrapping/unwrapping other keys.
 *
 * @param {object} options
 * @param {boolean} [options.extractable=true] Whether the key should be extractable for use outside the current context.
 * @returns {Promise<CryptoKey>} The generated key that can be used to wrap/unwrap other keys.
 */
export async function generateWrappingKey({ extractable = true } = {}) {
	return await generateSecretKey({ name: AES_KW, extractable, usages: WRAP_USAGES });
}

/**
 * Creates an ephemeral CryptoKey from a given password using the specified algorithm.
 *
 * @param {string} password The password to use for key derivation.
 * @param {Object} [options] Optional configuration options.
 * @param {string} [options.name='AES-GCM'] The name of the key algorithm (e.g., 'AES-GCM').
 * @param {number} [options.length=256] The desired key length in bits.
 * @param {string} [options.hash='SHA-256'] The hash algorithm to use for PBKDF2.
 * @param {number} [options.iterations=100000] The number of iterations for PBKDF2.
 * @param {boolean} [options.extractable=false] Whether the key can be extracted from the WebCrypto API.
 * @param {string[]} [options.usages=['encrypt','decrypt']] The intended usages for the key.
 * @param {ArrayBuffer|Uint8Array|string} [options.salt] Optional salt for deriving the key. If not given, the hash of the password will be used instead.
 * @returns {Promise<CryptoKey>} The generated CryptoKey.
 * @throws {TypeError} Thrown if the `password` is not a non-empty string or if the configuration options are invalid.
 */
export async function createSecretKeyFromPassword(pass, {
	name = AES_GCM,
	length = DEFAULT_KEY_LENGTH,
	hash: hashAlgo = SHA256,
	iterations = 100_000,
	extractable = false,
	usages = ENCRYPT_USAGES,
	salt,
} = {}) {
	if (typeof pass !== 'string' || pass.length === 0) {
		throw new TypeError('Key password must be a non-empty string.');
	} else if (typeof salt === 'string') {
		return await createSecretKeyFromPassword(pass, { name, length, hash, iterations, extractable, usages, salt: Uint8Array.fromBase64(salt) });
	} else if (! (salt instanceof ArrayBuffer || ArrayBuffer.isView(salt))) {
		return await createSecretKeyFromPassword(pass, {
			name, length, hash: hashAlgo, iterations, extractable, usages,
			salt: await hash(encoder.encode(`${name}:${hashAlgo}:${pass}`), SHA256)
		});
	} else {
		const encodedPass = encoder.encode(pass);
		const pbk = await crypto.subtle.importKey('raw', encodedPass, { name: 'PBKDF2' }, false, [DERIVE_KEY]);

		return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: hashAlgo }, pbk, { name, length }, extractable, usages);
	}
}

/**
 * Creates an ephemeral CryptoKey from a given password using the AES-KW algorithm for wrapping/unwrapping other keys.
 *
 * @param {string} pass The password to use for key derivation.
 * @param {object} options
 * @param {boolean} [options.extractable=false] Whether the key should be extractable from the WebCrypto API.
 * @returns {Promise<CryptoKey>} The generated wrapping `CryptoKey`.
 * @throws {TypeError} Thrown if password is not a string, is an empty string, or if the config to generate the key is invalid.
 */
export async function createWrappingKeyFromPassword(pass, { extractable = false } = {}) {
	return await createSecretKeyFromPassword(pass, { name: AES_KW, extractable, usages: WRAP_USAGES });
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
 * @param {Uint8Array} [options.iv] - Initialization vector (IV) used for encryption. If not given, an IV of the correct length for the algorithm will be generated.
 * @param {string} [options.output='ui8'] -  Output format for the encrypted data.
 * @returns {Promise<Uint8Array|string>} - The encrypted data. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the key is invalid, IV is invalid, or the data type is not supported for encryption.
 */
export async function encrypt(key, thing, {
	iv,
	output = DEFAULT_OUTPUT,
} = {}) {
	if (! (key instanceof CryptoKey) || ! key.usages.includes('encrypt')) {
		throw new TypeError('Invalid key.');
	} else if (typeof iv === 'undefined') {
		return await encrypt(key, thing, { iv: generateIV(key), output });
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

		return _encode(bytes, output);
	} else {
		throw new TypeError('Unsupported type/class to encrypt.');
	}
}

/**
 * A TransformStream that encrypts chunks of data.
 *
 * @extends {TransformStream<Uint8Array>}
 */
export class EncryptionStream extends TransformStream {
	/**
	 * Creates a new EncryptionStream.
	 *
	 * @param {CryptoKey} key - The encryption key. Must have the 'encrypt' usage flag.
	 * @param {Uint8Array} [iv] - The initialization vector. If not provided, a new one will be generated.
	 * @throws {TypeError} If the key is invalid or the IV is not a Uint8Array.
	 */
	constructor(key, iv) {
		if (! (key instanceof CryptoKey) || ! key.usages.includes('encrypt')) {
			throw new TypeError('Invalid key.');
		}

		if (typeof iv === 'undefined') {
			iv = generateIV(key);
		} else if (! (iv instanceof Uint8Array)) {
			throw new TypeError('Invalid IV.');
		}

		super({
			async transform(chunk, controller) {
				try {
					const encrypted = await crypto.subtle.encrypt({ name: key.algorithm.name, iv }, key, chunk);
					controller.enqueue(new Uint8Array(encrypted));
				} catch(err) {
					controller.error(err);
					controller.terminate();
				}
			}
		});
	}
}

/**
 * A TransformStream that decrypts chunks of data.
 *
 * @extends {TransformStream<Uint8Array>}
 */
export class DecryptionStream extends TransformStream {
	/**
	 * Creates a new DecryptionStream.
	 *
	 * @param {CryptoKey} key - The decryption key. Must have the 'decrypt' usage flag.
	 * @param {Uint8Array} iv - The initialization vector.
	 * @throws {TypeError} If the key is invalid or the IV is not a Uint8Array.
	 */
	constructor(key, iv) {
		if (! (key instanceof CryptoKey) || ! key.usages.includes('decrypt')) {
			throw new TypeError('Invalid key.');
		} else if (! (iv instanceof Uint8Array)) {
			throw new TypeError('Invalid IV.');
		} else {
			super({
				async transform(chunk, controller) {
					try {
						const decrypted = await crypto.subtle.decrypt({ name: key.algorithm.name, iv }, key, chunk);
						controller.enqueue(new Uint8Array(decrypted));
					} catch(err) {
						controller.error(err);
						controller.terminate();
					}
				}
			});
		}
	}
}

/**
 * Encrypts the given Response object using the provided key and initialization vector (IV).
 *
 * @param {CryptoKey} key - The encryption key. Must be a CryptoKey with the 'encrypt' usage flag.
 * @param {Uint8Array} iv - The initialization vector for encryption. Must be a non-empty Uint8Array.
 * @param {Response} resp - The Response object to encrypt.
 * @param {object} [options] - Optional options object.
 * @param {AbortSignal} [options.signal] - An AbortSignal to abort the encryption operation.
 * @returns {Response} - A new Response object containing the encrypted data.
 * @throws {TypeError} - If the key is invalid, the response is not a Response object, the IV is invalid, or the signal is aborted.
 */
export function encryptResponse(key, iv, resp, { signal } = {}) {
	if (! (key instanceof CryptoKey && key.usages.includes('encrypt'))) {
		throw new TypeError('Key is not a valid encryption key.');
	} else if (! (resp instanceof Response)) {
		throw new TypeError('Not a `Response`.');
	} else if (! (iv instanceof Uint8Array || iv.length === 0)) {
		throw new TypeError('IV must be a non-empty `Uint8Array`.');
	} else if (signal instanceof AbortSignal && signal.aborted) {
		throw signal.reason;
	} else {
		const headers = new Headers(resp.headers);
		const stream = resp.body.pipeThrough(new EncryptionStream(key, iv), { signal });
		headers.set(IV_HEADER, iv.toBase64({ alphabet: 'base64' }));

		return new Response(stream, {
			status: resp.status,
			statusText: resp.statusText,
			headers,
		});
	}
}

/**
 * Decrypts the given Response object using the provided key.
 * The IV for decryption is expected to be present in the Response headers under the `X-ENC-IV` key.
 *
 * @param {CryptoKey} key - The decryption key. Must be a CryptoKey with the 'decrypt' usage flag.
 * @param {Response} resp - The Response object to decrypt.
 * @param {object} [options] - Optional options object.
 * @param {AbortSignal} [options.signal] - An AbortSignal to abort the decryption operation.
 * @returns {Response} - A new Response object containing the decrypted data.
 * @throws {TypeError} - If the key is invalid, the response is not a Response object, the IV header is missing, or the signal is aborted.
 */
export function decryptResponse(key, resp, { signal } = {}) {
	if (! (key instanceof CryptoKey && key.usages.includes('decrypt'))) {
		throw new TypeError('Key is not a valid decryption key.');
	} else if (! (resp instanceof Response)) {
		throw new TypeError('Not a `Response`.');
	} else if (! resp.headers.has(IV_HEADER)) {
		throw new TypeError('Response is missing required IV header.');
	} else if (signal instanceof AbortSignal && signal.aborted) {
		throw signal.reason;
	} else {
		const iv = Uint8Array.fromBase64(resp.headers.get(IV_HEADER), { alphabet: 'base64' });
		const stream = resp.body.pipeThrough(new DecryptionStream(key, iv), { signal });
		const headers = new Headers(resp.headers);
		headers.delete(IV_HEADER);

		return new Response(stream, {
			status: resp.status,
			statusText: resp.statusText,
			headers,
		});
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
		return _encode(await decrypt(key, _decode(thing, input)), output);
	} else if (thing instanceof Blob) {
		return await decrypt(key, await thing.arrayBuffer(), { output });
	} else if (thing instanceof ArrayBuffer || ArrayBuffer.isView(thing)) {
		const ivLength = _getIVLength(key);
		const iv = thing.slice(0, ivLength);
		const payload = thing.slice(ivLength);
		const result = await crypto.subtle.decrypt({ ...key.algorithm, iv }, key, payload);

		return output === BUFFER ? result : _encode(new Uint8Array(result), output);
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

		return output === BUFFER ? result : _encode(new Uint8Array(result), output);
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
 * @param {Uint8Array} [options.iv] - Initialization vector (IV) used for encryption.
 * @param {string} [options.output='ui8'] - Output format for the signed data.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The signature for data. The exact type depends on the `output` option.
 * @throws {TypeError} - Thrown if the key is invalid, the hashing algorithm is unsupported, or the output format is invalid.
 */
export async function sign(key, thing, {
	algo = DEFAULT_ALGO,
	iv,
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
		return await verify(thing, _decode(expected, input).buffer, { algo });
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
	const expected = await decrypt(key, signature, { output: UI8_ARR, input });
	return await verify(source, expected, { algo, input: BUFFER });
}

/**
 * Encrypts a file and wraps it in a custom file extension and MIME type.
 *
 * @param {CryptoKey} key A cryptographic key for encryption.
 * @param {File} file The file to encrypt.
 * @param {object} options
 * @param {string} [options.name] The name of the encrypted file. Defaults to a timestamp with a custom extension.
 * @param {*} [options.metadata=null] Additional metadata to store with the encrypted file.
 * @param {Uint8Array|void} [options.iv] Optional Inititialization Vector.
 * @returns {Promise<File>} A new File instance with encrypted content.
 * @throws {TypeError} If `file` is not a valid File object or `key` is not a valid `CryptoKey`
 */
export async function encryptFile(key, file, {
	name,
	metadata = null,
	iv,
} = {}) {
	if (typeof iv === 'undefined') {
		return await encryptFile(key, file, { name, metadata, iv: generateIV(key) });
	} else if (! (file instanceof File)) {
		throw new TypeError('encryptFile requires a File object.');
	} else {
		// Create file header of fixed length
		const header = new Uint8Array(HEADER_SIZE);
		// Fixed length "Magic Number"
		const magicStr = `${key.algorithm.name.toLowerCase()}-${key.algorithm.length} ${FILE_VERSION}`.padEnd(MAGIC_STR_LEN,' ');
		const magicBytes = encoder.encode(magicStr);

		// Fill the header data with magic numbers, iv length, iv, and encoded metadata
		header.set(magicBytes, 0);
		header.set([iv.length], magicBytes.length);
		header.set(iv, magicBytes.length + 1);
		header.set(encoder.encode(JSON.stringify(metadata)), magicBytes.length + iv.length + 1);

		// Create File header with file metadata, prefixed by header length for predictable parsing
		const fileHeader = encoder.encode(`${file.name},${file.type},${file.lastModified.toString()}`);
		const bytes = await file.bytes();
		const data = new Uint8Array(fileHeader.length + bytes.length + 1);
		data.set([fileHeader.length], 0);
		data.set(fileHeader, 1);
		data.set(bytes, fileHeader.length + 1);

		const encrypted = new Uint8Array(await crypto.subtle.encrypt({ ...key.algorithm, iv }, key, data));

		// Resulting data is the header + encrypted payload
		const result = new Uint8Array(header.length + encrypted.length);
		result.set(header, 0);
		result.set(encrypted, header.length);

		return new File([result], name ?? `${file.name}${FILE_EXT}`, {
			type: `application/x-${key.algorithm.name.toLowerCase()}-${key.algorithm.length}+encrypted`
		});
	}
}

/**
 * Decrypts a file encrypted by `encryptFile`.
 *
 * @param {CryptoKey} key A cryptographic key for decryption.
 * @param {Blob|File} file The file to decrypt (Blob ok since name is not important)
 * @return {Promise<File>} A new File instance with decrypted content, having name and metadata of the original.
 * @throws {TypeError} If `file` is not a valid File object or `key` is not a valid `CryptoKey`
 */
export async function decryptFile(key, file) {
	if (! (file instanceof Blob)) {
		throw new TypeError('decryptFile requires a File or Blob object.');
	} else {
		// Get the file header and encrypted payload
		const bytes = await file.bytes();
		const header = bytes.subarray(0, HEADER_SIZE);
		const payload = bytes.subarray(HEADER_SIZE);

		// IV length is the first byte after the fixed length magic number
		const iv = header.subarray(MAGIC_STR_LEN + 1, MAGIC_STR_LEN + 1 + header[MAGIC_STR_LEN]);
		const decrypted = new Uint8Array(await crypto.subtle.decrypt({ ...key.algorithm, iv }, key, payload));

		// [header length byte, name, type, lastModified, ...file data]
		const decryptedHeader = decoder.decode(decrypted.subarray(1, decrypted[0] + 1));
		const [name, type, lastModified] = decryptedHeader.split(',');

		return new File([decrypted.subarray(decryptedHeader.length + 1)], name, { type, lastModified: parseInt(lastModified) });
	}
}

/**
 * Wraps a cryptographic key using a wrapping key.
 *
 * @param {CryptoKey} wrappingKey - The key to use for wrapping.
 * @param {CryptoKey} key - The key to be wrapped.
 * @param {object} [options] - Optional options for wrapping.
 * @param {string} [options.format='jwk'] - The format of the wrapped key.
 * @param {object} [options.wrapAlgo={name:'AES-KW'}] - The wrapping algorithm to use.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The wrapped key in the specified output format.
 */
export async function wrapKey(wrappingKey, key, {
	format = 'jwk',
	wrapAlgo = { name: AES_KW },
	output = BUFFER,
} = {}) {
	const result = await crypto.subtle.wrapKey(format, key, wrappingKey, wrapAlgo);

	return output !== BUFFER ? _encode(result, output) : result;
}

/**
 * Wraps a cryptographic key using a wrapping key, returning an encoded format for later unwrappeing.
 *
 * @param {CryptoKey} wrappingKey - The key to use for wrapping.
 * @param {CryptoKey} key - The key to be wrapped.
 * @param {object} [options] - Optional options for wrapping.
 * @param {string} [options.format='jwk'] - The format of the wrapped key.
 * @param {string} [options.output='base64'] The output format for the wrapped key.
 * @returns {Promise<ArrayBuffer|Uint8Array|string>} - The wrapped key in the specified output format, along with key data.
 */
export async function wrapAndEncodeKey(wrappingKey, key, {
	format = 'jwk',
	output = BASE64,
} = {}) {
	const wrapped = await wrapKey(wrappingKey, key, { format, wrapAlgo: wrappingKey.algorithm, output: UI8_ARR });
	const header = encoder.encode(JSON.stringify({ format, wrapAlgo: wrapKey.algorithm, usages: key.usages, keyAlgo: key.algorithm }));
	const bytes = new Uint8Array(wrapped.length + header.length + 1);

	// Store the header length in the first byte so it can be used for decoding later
	bytes.set([header.length], 0, 1);
	// Next, store the JSON encoded header data
	bytes.set(header, 1, header.length + 1);
	// The rest of the bytes are all key data
	bytes.set(wrapped, header.length + 1);

	switch(output) {
		case UI8_ARR:
			return bytes;

		case BUFFER:
			return bytes.buffer;

		default:
			return _encode(bytes, output);
	}
}

/**
 * Unwraps a cryptographic key using an unwrapping key.
 *
 * @param {CryptoKey} unwrappingKey - The key to use for unwrapping.
 * @param {ArrayBufferView|string} wrappedKey - The wrapped key to be unwrapped.
 * @param {object} [options] - Optional options for unwrapping.
 * @param {string} [options.format='jwk'] - The format of the wrapped key.
 * @param {object} [options.unwrapAlgo={name:'AES-KW'}] - The unwrapping algorithm to use.
 * @param {object} [options.unwrappedKeyAlgo={name:AES_GCM}] - The algorithm of the unwrapped key.
 * @param {boolean} [options.extractable=true] - Whether the unwrapped key is extractable.
 * @param {string[]} [options.usages=KEY_OPS] - The key usages of the unwrapped key.
 * @param {string} [options.input=BASE64] - The input format of the wrapped key.
 * @returns {Promise<CryptoKey>} - The unwrapped key.
 */
export async function unwrapKey(unwrappingKey, wrappedKey, {
	format = 'jwk',
	unwrapAlgo = { name: 'AES-KW' },
	unwrappedKeyAlgo = { name: AES_GCM },
	extractable = true,
	usages = ENCRYPT_USAGES,
	input = BASE64,
} = {}) {
	if (typeof wrappedKey === 'string') {
		return await unwrapKey(unwrappingKey, _encode(wrappedKey, input).buffer, { format, unwrapAlgo, unwrappedKeyAlgo, extractable, usages });
	} else if (wrappedKey instanceof ArrayBuffer || ArrayBuffer.isView(wrappedKey)) {
		return await crypto.subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgo, unwrappedKeyAlgo, extractable, usages);
	} else {
		throw new TypeError('Invalid wrapped key data.');
	}
}

/**
 * Unwraps and decodes a cryptographic key.

 * @param {CryptoKey} key - The key to use for unwrapping.
 * @param {string|ArrayBuffer|Uint8Array} wrappedKeyData - The wrapped key data to be unwrapped and decoded.
 * @param {object} [options] - Optional options for unwrapping and decoding.
 * @param {string} [options.input='base64'] - The input format of the wrapped key data.
 * @param {boolean} [options.extractable=true] - Whether the unwrapped key is extractable.
 * @returns {Promise<CryptoKey>} - The unwrapped and decoded key.
 */
export async function unwrapAndDecodeKey(key, wrappedKeyData, {
	input = BASE64,
	extractable = true,
} = {}) {
	if (typeof wrappedKeyData === 'string') {
		return await unwrapAndDecodeKey(key, _decode(wrappedKeyData, input), { extractable });
	} else if (wrappedKeyData instanceof ArrayBuffer) {
		return await unwrapAndDecodeKey(key, new Uint8Array(wrappedKeyData), { extractable });
	} else if (wrappedKeyData instanceof Uint8Array) {
		const length = wrappedKeyData[0];
		const { format, wrapAlgo, usages, keyAlgo } = JSON.parse(decoder.decode(wrappedKeyData.slice(1, length + 1)));
		const keyData = wrappedKeyData.slice(length + 1);
		const unwrappedKey = await unwrapKey(key, keyData, { format, unwrapAlgo: wrapAlgo, unwrappedKeyAlgo: keyAlgo, usages, extractable });

		return unwrappedKey;
	} else {
		throw new TypeError('Wrapped key data must be an encoded string, a `Uint8Array`, or an `ArrayBuffer`.');
	}
}
