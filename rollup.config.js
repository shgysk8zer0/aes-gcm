import nodeResolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';

const external = ['@shgysk8zer0/polyfills'];

export default [{
	input: 'aes-gcm.js',
	plugins: [nodeResolve()],
	external,
	output: [{
		file: 'aes-gcm.cjs',
		format: 'cjs',
	}, {
		file: 'aes-gcm.min.js',
		external,
		format: 'esm',
		plugins: [terser()],
		sourcemap: true,
	}],
}];
