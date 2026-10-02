import { defineConfig } from 'tsup';
import pkg from './package.json';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    express: 'src/express.ts',
    next: 'src/next.ts',
    testing: 'src/testing.ts',
    cli: 'src/cli/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: {
    resolve: true,
  },
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
  treeshake: true,
  define: {
    __VERIHOOK_VERSION__: JSON.stringify(pkg.version),
  },
});
