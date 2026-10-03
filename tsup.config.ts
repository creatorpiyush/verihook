import { readdirSync } from 'node:fs';
import { defineConfig } from 'tsup';
import pkg from './package.json';

// One entry per provider (`verihook/stripe`, ...) from src/entries.
const providerEntries = Object.fromEntries(
  readdirSync('src/entries')
    .filter((file) => file.endsWith('.ts'))
    .map((file) => [file.slice(0, -3), `src/entries/${file}`]),
);

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    express: 'src/express.ts',
    next: 'src/next.ts',
    testing: 'src/testing.ts',
    fastify: 'src/fastify.ts',
    hono: 'src/hono.ts',
    h3: 'src/h3.ts',
    sveltekit: 'src/sveltekit.ts',
    remix: 'src/remix.ts',
    astro: 'src/astro.ts',
    lambda: 'src/lambda.ts',
    nestjs: 'src/nestjs.ts',
    cli: 'src/cli/index.ts',
    ...providerEntries,
  },
  format: ['cjs', 'esm'],
  dts: {
    resolve: true,
  },
  splitting: true,
  sourcemap: true,
  clean: true,
  minify: false,
  treeshake: true,
  define: {
    __VERIHOOK_VERSION__: JSON.stringify(pkg.version),
  },
});
