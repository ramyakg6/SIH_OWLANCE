/**
 * Frontend smoke test.
 *
 *   node scripts/smoke-test.mjs
 *
 * `vite build` only proves the bundle compiles, and the production minifier
 * reorders declarations -- so a module-initialisation error (a temporal dead
 * zone reference, a throw at module scope) can pass the build while still
 * producing a blank screen under `npm run dev`. Interaction bugs are invisible
 * to both.
 *
 * This covers the two classes that have actually shipped broken here:
 *   1. module init   -- every source module is evaluated through Vite's dev
 *                       pipeline, which is what `npm run dev` runs.
 *   2. slider drag   -- the optimizer's budget slider is dragged with real
 *                       pointer events and the emitted value is checked.
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------
// DOM environment
// ---------------------------------------------------------------------------
const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>',
  { url: 'http://localhost:5173/', pretendToBeVisual: true });
const W = dom.window;

for (const k of ['window','document','HTMLElement','Element','Node','SVGElement',
                 'Event','MouseEvent','KeyboardEvent','getComputedStyle','DOMRect','CSS']) {
  if (W[k] !== undefined) globalThis[k] = W[k];
}
// jsdom ships no PointerEvent, and the slider listens for pointer events.
if (!W.PointerEvent) {
  W.PointerEvent = class PointerEvent extends W.MouseEvent {
    constructor(type, init = {}) {
      super(type, init);
      this.pointerId = init.pointerId ?? 1;
      this.pointerType = init.pointerType ?? 'mouse';
      this.isPrimary = init.isPrimary ?? true;
    }
  };
}
globalThis.PointerEvent = W.PointerEvent;
globalThis.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
globalThis.matchMedia = () => ({ matches: false, addListener(){}, removeListener(){},
  addEventListener(){}, removeEventListener(){}, dispatchEvent(){ return false; } });
// The backend is not running. Every request failing is exactly the path that
// must still render.
globalThis.fetch = () => Promise.reject(new Error('smoke test: backend offline'));
globalThis.localStorage = W.localStorage;
globalThis.ResizeObserver = class { observe(){} unobserve(){} disconnect(){} };
W.HTMLElement.prototype.setPointerCapture = function(){};
W.HTMLElement.prototype.releasePointerCapture = function(){};
W.HTMLElement.prototype.hasPointerCapture = function(){ return false; };
W.Element.prototype.getBoundingClientRect = function(){
  return { x:0, y:0, width:400, height:20, top:0, left:0, right:400, bottom:20, toJSON(){} };
};

const failures = [];
const log = console.error.bind(console);
console.error = () => {};              // React logs render failures here
process.on('unhandledRejection', (r) => failures.push('unhandledRejection: ' + r));

const React = (await import('react')).default;
const { createRoot } = await import('react-dom/client');
const server = await createServer({
  root, logLevel: 'error', server: { middlewareMode: true, hmr: false }, appType: 'custom',
});
const tick = (ms = 250) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// 1. Module initialisation
// ---------------------------------------------------------------------------
const MODULES = ['/src/lib/api.js', '/src/OwLance.jsx', '/src/App.jsx'];
for (const path of MODULES) {
  try {
    const mod = await server.ssrLoadModule(path);
    if (path.endsWith('OwLance.jsx') && typeof mod.default !== 'function') {
      failures.push(`${path}: expected a default-exported component`);
    }
  } catch (err) {
    failures.push(`${path}: ${(err && err.message) || err}`);
    break;   // a module-init failure cascades
  }
}

// ---------------------------------------------------------------------------
// 2. Budget slider: drag must emit the same shape it was given
// ---------------------------------------------------------------------------
// Base UI decides "is this a range slider" differently in two places:
//   SliderRoot.js    range = Array.isArray(valueUnwrapped)   -> array
//   SliderControl.js range = values.length > 1               -> number
// A single-thumb slider controlled with an array therefore emits a bare
// number on drag. The wrapper normalises this; without it, budget[0] becomes
// undefined and the optimizer page blanks on the first drag.
if (!failures.length) {
  try {
    const { Slider } = await server.ssrLoadModule('/src/components/ui/slider.jsx');
    const seen = [];

    function Harness() {
      const [budget, setBudget] = React.useState([15000]);
      return React.createElement('div', null,
        React.createElement('span', { id: 'out' },
          String(Array.isArray(budget) ? budget[0] : `NOT-AN-ARRAY(${budget})`)),
        React.createElement(Slider, {
          value: budget, max: 40000, step: 1000,
          onValueChange: (v) => { seen.push(v); setBudget(v); },
        }));
    }

    const container = W.document.getElementById('root');
    createRoot(container).render(React.createElement(Harness));
    await tick(700);

    const thumb = container.querySelector('[data-slot="slider-thumb"]');
    const control = container.querySelector('[data-slot="slider"] > *');
    if (!thumb) throw new Error('slider thumb did not render');

    const fire = (el, type, x) => el.dispatchEvent(new W.PointerEvent(type, {
      bubbles: true, cancelable: true, view: W, clientX: x, clientY: 10,
      button: 0, buttons: 1, pointerId: 1, pointerType: 'mouse', isPrimary: true }));

    fire(thumb, 'pointerdown', 150);
    await tick(100);
    for (const x of [200, 260, 320]) { fire(W.document, 'pointermove', x); await tick(60); }
    fire(W.document, 'pointerup', 320);
    await tick(300);

    const shown = container.querySelector('#out').textContent;
    if (shown.startsWith('NOT-AN-ARRAY') || shown === 'undefined') {
      failures.push(`slider drag emitted the wrong shape: #out is "${shown}" ` +
                    `(callback saw ${JSON.stringify(seen.at(-1))})`);
    }
    if (seen.some((v) => !Array.isArray(v))) {
      failures.push(`slider emitted a non-array: ${JSON.stringify(seen.find((v) => !Array.isArray(v)))}`);
    }

    // Pressing the track directly goes through the same path.
    if (control) {
      fire(control, 'pointerdown', 40); await tick(80);
      fire(W.document, 'pointerup', 40); await tick(250);
      const after = container.querySelector('#out').textContent;
      if (after.startsWith('NOT-AN-ARRAY') || after === 'undefined') {
        failures.push(`slider track press emitted the wrong shape: "${after}"`);
      }
    }
  } catch (err) {
    failures.push(`slider interaction: ${(err && err.message) || err}`);
  }
}

await server.close();
console.error = log;

if (failures.length) {
  log('\n  FAIL  Frontend smoke test\n');
  [...new Set(failures)].forEach((f) => log(`    - ${f}`));
  log('');
  process.exit(1);
}

log('\n  PASS  Frontend smoke test');
log(`    ${MODULES.length} source modules evaluated through Vite's dev pipeline`);
log('    budget slider drag and track press emit a stable value shape');
log('    backend was offline throughout\n');
process.exit(0);
