export class XORTransformStream extends TransformStream {
	constructor(bytes) {
		if (! (bytes instanceof Uint8Array) || bytes.length === 0) {
			throw new TypeError('Cannot xor without a non-empty Uint8Array.');
		} else {
			super({
				transform(chunk, controller) {
					try {
						if (chunk.length > bytes.length) {
							const transformedChunk = new Uint8Array(chunk.length);

							for (let n = 0; n < chunk.length; n += bytes.length) {
								transformedChunk.set(
									chunk.subarray(n, n + bytes.length).map((byte, i) => byte ^ bytes[i]),
									n
								);
							}

							controller.enqueue(transformedChunk);
						} else {
							controller.enqueue(chunk.map((byte, i) => byte ^ bytes[i]));
						}
					} catch(err) {
						controller.error(err);
						controller.terminate();
					}
				}
			});
		}
	}
}
