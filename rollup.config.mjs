import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';

export default {
	input: 'lib/index.js',
  plugins: [
    commonjs(),
    nodeResolve(),
  ],
	output: {
		file: 'dist/chacha20.js',
		format: 'umd',
    name: 'chacha20',
	}
};
