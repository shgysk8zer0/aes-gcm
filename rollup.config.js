import terser from '@rollup/plugin-terser';

export default [{
	input: 'aes-gcm.js',
	output: [{
		file: 'aes-gcm.cjs',
		format: 'cjs',
	}, {
		file: 'aes-gcm.min.js',
		format: 'esm',
		plugins: [terser()],
		sourcemap: true,
	}],
}];
