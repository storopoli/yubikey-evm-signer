#!/usr/bin/env node
/**
 * CI verification script for the demo UI and WASM/npm package artifacts.
 *
 * Usage:
 *   node scripts/verify-demo.mjs                # Verify demo HTML/JS integrity
 *   node scripts/verify-demo.mjs --check-wasm   # Also verify packages/npm/dist artifacts & exports
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const checkWasm = process.argv.includes('--check-wasm');

const errors = [];

function fail(message) {
    errors.push(message);
}

// 1. Verify demo/app.js parses cleanly with `node --check`
const appJsPath = resolve(repoRoot, 'demo/app.js');
try {
    execFileSync(process.execPath, ['--check', appJsPath], { stdio: 'pipe' });
} catch (err) {
    fail(`node --check demo/app.js failed: ${err.stderr?.toString() || err.message}`);
}

const appJs = readFileSync(appJsPath, 'utf8');
const indexHtmlPath = resolve(repoRoot, 'demo/index.html');
const indexHtml = readFileSync(indexHtmlPath, 'utf8');

// 2. Verify every document.getElementById('...') in demo/app.js exists in demo/index.html
const htmlIds = new Set();
for (const match of indexHtml.matchAll(/\bid="([^"]+)"/g)) {
    htmlIds.add(match[1]);
}

const referencedIds = new Set();
for (const match of appJs.matchAll(/document\.getElementById\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    referencedIds.add(match[1]);
}

if (referencedIds.size === 0) {
    fail('Expected demo/app.js to reference DOM IDs via document.getElementById(...)');
}

for (const id of referencedIds) {
    if (!htmlIds.has(id)) {
        fail(`demo/app.js references element ID '${id}', which is missing from demo/index.html`);
    }
}

// 3. Verify every target="_blank" anchor in demo/index.html has rel="noopener noreferrer"
for (const match of indexHtml.matchAll(/<a\b[^>]*>/gi)) {
    const tag = match[0];
    if (/\btarget=["']_blank["']/i.test(tag)) {
        const relMatch = tag.match(/\brel=["']([^"']+)["']/i);
        const relTokens = relMatch
            ? new Set(relMatch[1].toLowerCase().split(/\s+/).filter(Boolean))
            : new Set();
        if (!relTokens.has('noopener') || !relTokens.has('noreferrer')) {
            fail(`Anchor with target="_blank" must include rel="noopener noreferrer": ${tag}`);
        }
    }
}

// 4. Verify demo/index.html has no stale false WebUSB compatibility claims and documents Issue #14 + Bridge
const forbiddenClaims = ['Works well', 'Works with USB OTG'];
for (const phrase of forbiddenClaims) {
    if (indexHtml.includes(phrase)) {
        fail(`demo/index.html still contains stale WebUSB claim: "${phrase}"`);
    }
}

const requiredDocMarkers = ['Local PC/SC Bridge', '0x1050', '0x0B', 'usb_blocklist.cc'];
for (const marker of requiredDocMarkers) {
    if (!indexHtml.includes(marker)) {
        fail(`demo/index.html is missing required Issue #14 / bridge documentation marker: "${marker}"`);
    }
}

// 5. Optional: verify WASM build outputs and TypeScript declarations in packages/npm/dist
if (checkWasm) {
    const distDir = resolve(repoRoot, 'packages/npm/dist');
    const requiredFiles = [
        'yubikey_evm_signer_wasm.js',
        'yubikey_evm_signer_wasm_bg.wasm',
        'yubikey_evm_signer_wasm.d.ts',
    ];
    for (const file of requiredFiles) {
        const fullPath = resolve(distDir, file);
        if (!existsSync(fullPath)) {
            fail(`Missing required WASM artifact: packages/npm/dist/${file}`);
        }
    }

    const forbiddenDistFiles = ['.gitignore', 'package.json'];
    for (const file of forbiddenDistFiles) {
        const fullPath = resolve(distDir, file);
        if (existsSync(fullPath)) {
            fail(`packages/npm/dist must not contain leftover wasm-pack file: ${file}`);
        }
    }

    const dtsPath = resolve(distDir, 'yubikey_evm_signer_wasm.d.ts');
    if (existsSync(dtsPath)) {
        const dts = readFileSync(dtsPath, 'utf8');
        const requiredExports = [
            'connectBridge',
            'connect',
            'setSlot',
            'authenticateManagementKey',
            'isWebUsbSupported',
            'getVersion',
        ];
        for (const sym of requiredExports) {
            if (!new RegExp(`\\b${sym}\\b`).test(dts)) {
                fail(`packages/npm/dist/yubikey_evm_signer_wasm.d.ts is missing expected export '${sym}'`);
            }
        }
    }
}

if (errors.length > 0) {
    console.error('Demo / WASM verification failed:');
    for (const err of errors) {
        console.error(`  - ${err}`);
    }
    process.exit(1);
}

console.log(
    checkWasm
        ? `OK: verified demo/app.js (${referencedIds.size} IDs), demo/index.html, and packages/npm/dist WASM exports.`
        : `OK: verified demo/app.js (${referencedIds.size} IDs) and demo/index.html.`
);
