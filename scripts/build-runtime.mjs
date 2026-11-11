import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { minifyWidget } from './minify-widget.mjs';

export async function composeRuntime({ widgetId = null, minify = true } = {}) {
  if (widgetId !== null && (typeof widgetId !== 'string' || !widgetId.length || widgetId.length > 256)) throw new Error('Invalid shared widget ID');
  const paths = ['tgcloud/lib/input.js', 'tgcloud/lib/widget.js', 'scripts/runtime-bot.js'];
  const sources = await Promise.all(paths.map(name => readFile(new URL('../' + name, import.meta.url), 'utf8')));
  if (sources.some(source => /^import\s/m.test(source))) throw new Error('Unexpected runtime import');
  if (minify) {
    const start = sources[1].indexOf('function runWidget(');
    const end = sources[1].indexOf('\nexport function renderWidget(', start);
    if (start < 0 || end < 0) throw new Error('Cannot locate widget function boundary');
    const original = sources[1].slice(start, end).trimEnd();
    sources[1] = sources[1].slice(0, start) + await minifyWidget(original) + sources[1].slice(start + original.length);
  }
  return "import { api } from 'sdk';\n\n" + sources.join('\n\n') +
    '\n\nexport const sharedWidgetId = ' + JSON.stringify(widgetId) + ';\n' +
    'export default createBot(api, { parse: parseInput, render: renderWidget, widgetId: sharedWidgetId }).message;\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const widgetId = process.argv[2] || null;
  const source = await composeRuntime({ widgetId });
  process.stdout.write(source);
}
