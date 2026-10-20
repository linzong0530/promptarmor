// PromptArmor test runner — node tests/run.mjs
// Loads the detector and the payload corpus, prints interception rate for
// attacks (flag + block count as intercepted) and pass rate for benign
// inputs, and lists every miss / false positive individually.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/detector.js';

const here = dirname(fileURLToPath(import.meta.url));
const payloads = JSON.parse(readFileSync(join(here, '..', 'data', 'payloads.json'), 'utf8'));

const TARGET_INTERCEPT = 85; // %
const TARGET_BENIGN_PASS = 90; // %

let intercepted = 0;
const misses = [];
for (const item of payloads.attacks) {
  const r = analyze(item.text);
  if (r.verdict === 'allow') {
    misses.push({ item, r });
  } else {
    intercepted++;
  }
}

let passed = 0;
const falsePositives = [];
for (const item of payloads.benign) {
  const r = analyze(item.text);
  if (r.verdict === 'allow') {
    passed++;
  } else {
    falsePositives.push({ item, r });
  }
}

const interceptRate = (intercepted / payloads.attacks.length) * 100;
const benignRate = (passed / payloads.benign.length) * 100;

console.log('=== PromptArmor detector test ===');
console.log(`Attacks : ${intercepted}/${payloads.attacks.length} intercepted (flag+block) = ${interceptRate.toFixed(1)}%  (target >= ${TARGET_INTERCEPT}%)`);
console.log(`Benign  : ${passed}/${payloads.benign.length} allowed = ${benignRate.toFixed(1)}%  (target >= ${TARGET_BENIGN_PASS}%)`);

if (misses.length) {
  console.log('\n--- MISSED ATTACKS (verdict=allow) ---');
  for (const { item, r } of misses) {
    console.log(`[${item.category}] score=${r.score} :: ${item.text}`);
  }
}
if (falsePositives.length) {
  console.log('\n--- FALSE POSITIVES (benign flagged/blocked) ---');
  for (const { item, r } of falsePositives) {
    console.log(`verdict=${r.verdict} score=${r.score} rules=${r.hits.map((h) => h.rule).join(',')} :: ${item.text}`);
  }
}

// Per-category attack breakdown
const byCat = {};
for (const item of payloads.attacks) {
  byCat[item.category] ??= { total: 0, hit: 0 };
  byCat[item.category].total++;
  if (analyze(item.text).verdict !== 'allow') byCat[item.category].hit++;
}
console.log('\n--- Per-category interception ---');
for (const [cat, v] of Object.entries(byCat)) {
  console.log(`${cat}: ${v.hit}/${v.total}`);
}

const ok = interceptRate >= TARGET_INTERCEPT && benignRate >= TARGET_BENIGN_PASS;
console.log(`\nRESULT: ${ok ? 'PASS' : 'FAIL'}`);
process.exit(ok ? 0 : 1);
