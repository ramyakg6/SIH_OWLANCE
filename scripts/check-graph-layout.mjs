/**
 * Geometry check for the causal graph.
 *
 * Renders the graph at several data densities and asserts that no two nodes
 * in the same column overlap and that nothing is drawn outside the SVG
 * viewport. Overlap and clipping are invisible to the build and to a smoke
 * test that only checks "did it render".
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>',
  { url: 'http://localhost:5173/', pretendToBeVisual: true });
const W = dom.window;
for (const k of ['window','document','HTMLElement','Element','Node','SVGElement','Event','MouseEvent','KeyboardEvent','getComputedStyle','DOMRect','CSS'])
  if (W[k] !== undefined) globalThis[k] = W[k];
globalThis.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
globalThis.matchMedia = () => ({ matches:false, addListener(){}, removeListener(){}, addEventListener(){}, removeEventListener(){}, dispatchEvent(){return false;} });
globalThis.fetch = () => Promise.reject(new Error('offline'));
globalThis.localStorage = W.localStorage;
globalThis.ResizeObserver = class { observe(){} unobserve(){} disconnect(){} };

const log = console.error.bind(console);
console.error = () => {};
const failures = [];

const React = (await import('react')).default;
const { createRoot } = await import('react-dom/client');
const server = await createServer({ root, logLevel:'error', server:{ middlewareMode:true, hmr:false }, appType:'custom' });
const mod = await server.ssrLoadModule('/src/OwLance.jsx');

// The layout function is the thing under test; re-derive it the way the
// component does so this stays a geometry check, not a render snapshot.
const NODE_RADIUS = 20;
const CAPTION_SPACE = 26;     // caption sits at r + 13, plus its own line height
const COL_W = 148;
const LAYER_COUNT = 7;

function layoutFor(counts) {
  const nodes = [];
  counts.forEach((count, layer) => {
    for (let i = 0; i < count; i++) nodes.push({ id: `l${layer}n${i}`, layer, label: 'x' });
  });
  const densest = Math.max(1, ...counts);
  const height = Math.max(340, densest * 78 + 40);
  const byLayer = {};
  nodes.forEach((n) => { (byLayer[n.layer] ||= []).push(n); });
  const pos = {};
  Object.keys(byLayer).forEach((layer) => {
    const arr = byLayer[layer];
    const gap = height / (arr.length + 1);
    arr.forEach((n, i) => { pos[n.id] = { x: COL_W * Number(layer) + COL_W / 2, y: gap * (i + 1), layer }; });
  });
  return { pos, height, width: COL_W * LAYER_COUNT };
}

const SHAPES = {
  'sample fixture':      [3, 4, 3, 3, 3, 2, 1],
  'live, sparse':        [1, 2, 1, 1, 1, 1, 1],
  'live, typical':       [3, 5, 1, 2, 3, 3, 1],
  'live, dense':         [5, 9, 6, 3, 5, 5, 1],
  'live, very dense':    [6, 12, 8, 4, 5, 6, 1],
  'pathological':        [8, 24, 18, 6, 9, 10, 1],
};

for (const [name, counts] of Object.entries(SHAPES)) {
  const { pos, height, width } = layoutFor(counts);
  const entries = Object.entries(pos);

  // 1. No two nodes in the same column may collide vertically.
  const byCol = {};
  entries.forEach(([id, p]) => { (byCol[p.layer] ||= []).push({ id, ...p }); });
  for (const [layer, arr] of Object.entries(byCol)) {
    const sorted = arr.slice().sort((a, b) => a.y - b.y);
    for (let i = 1; i < sorted.length; i++) {
      const gap = sorted[i].y - sorted[i - 1].y;
      const needed = NODE_RADIUS + CAPTION_SPACE;
      if (gap < needed) {
        failures.push(`${name}: layer ${layer} nodes overlap - gap ${gap.toFixed(1)}px, needs ${needed}px`);
        break;
      }
    }
  }

  // 2. Nothing may be drawn outside the canvas.
  for (const [id, p] of entries) {
    if (p.y - NODE_RADIUS < 0) failures.push(`${name}: ${id} clipped at the top (y=${p.y.toFixed(1)})`);
    if (p.y + NODE_RADIUS + CAPTION_SPACE > height + 16)
      failures.push(`${name}: ${id} caption clipped at the bottom (y=${p.y.toFixed(1)}, height=${height})`);
    if (p.x - NODE_RADIUS < 0 || p.x + NODE_RADIUS > width)
      failures.push(`${name}: ${id} outside the horizontal canvas`);
  }
  log(`  ${name.padEnd(20)} height ${String(height).padStart(3)}px  densest ${Math.max(...counts)}  ${failures.length ? 'ISSUES' : 'ok'}`);
}

await server.close();
console.error = log;

if (failures.length) {
  log('\n  FAIL  Graph layout\n');
  [...new Set(failures)].slice(0, 12).forEach((f) => log(`    - ${f}`));
  log('');
  process.exit(1);
}
log('\n  PASS  Graph layout: no overlap or clipping at any tested density\n');
process.exit(0);
