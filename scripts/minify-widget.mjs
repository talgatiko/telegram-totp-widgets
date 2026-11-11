import { createRequire } from 'node:module';

const { minify } = createRequire(new URL('./minifier/package.json', import.meta.url))('terser');

export async function minifyWidget(source) {
  if (typeof source !== 'string' || !source.startsWith('function runWidget(')) throw new Error('Expected runWidget function source');
  const result = await minify(source, {
    ecma: 2020,
    compress: { passes: 3, unsafe: false, unsafe_math: false },
    mangle: { reserved: ['runWidget'], nth_identifier: { get: index => 'v' + index.toString(36) } },
    format: { comments: false, ascii_only: false },
  });
  if (!result.code || !result.code.startsWith('function runWidget(')) throw new Error('Minifier did not preserve runWidget');
  return result.code;
}
