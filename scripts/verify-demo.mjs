#!/usr/bin/env node
/**
 * CI verification script for the demo UI and WASM/npm package artifacts.
 *
 * Usage:
 *   node scripts/verify-demo.mjs
 *       Verify demo HTML/JS integrity (DOM IDs, links, CSP, no inline handlers), and
 *       that crates/signer-wasm/src exports (#[wasm_bindgen]) every WASM name and
 *       YubiKeyDevice method demo/app.js uses.
 *   node scripts/verify-demo.mjs --check-wasm [--wasm-dir <path>]
 *       Also verify the wasm-bindgen output in <path> (default: packages/npm/dist)
 *       exports everything demo/app.js imports from the WASM module and every
 *       method demo/app.js calls on the device. When <path> is packages/npm/dist,
 *       also verify the npm package layout (no wasm-pack leftovers, license files).
 *       A relative <path> is resolved against the current working directory.
 *
 * Exit codes: 0 when every check passes, 1 when any check fails, 2 on usage errors.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const npmPackageDir = resolve(repoRoot, 'packages/npm');
const npmDistDir = resolve(npmPackageDir, 'dist');

function usage(message) {
    console.error(`verify-demo: ${message}`);
    console.error('Usage: node scripts/verify-demo.mjs [--check-wasm [--wasm-dir <path>]]');
    process.exit(2);
}

let checkWasm = false;
let wasmDirArg = null;
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--check-wasm') {
        checkWasm = true;
    } else if (arg === '--wasm-dir') {
        if (i + 1 >= args.length || args[i + 1].startsWith('--')) {
            usage('--wasm-dir requires a path');
        }
        wasmDirArg = args[++i];
    } else if (arg.startsWith('--wasm-dir=')) {
        wasmDirArg = arg.slice('--wasm-dir='.length);
        if (!wasmDirArg) usage('--wasm-dir requires a path');
    } else {
        usage(`unknown argument '${arg}'`);
    }
}
if (wasmDirArg !== null && !checkWasm) {
    usage('--wasm-dir is only meaningful together with --check-wasm');
}

const wasmDir = wasmDirArg === null ? npmDistDir : resolve(process.cwd(), wasmDirArg);
const isNpmDist = wasmDir === npmDistDir;
const wasmDirLabel = relative(repoRoot, wasmDir).startsWith('..') ? wasmDir : relative(repoRoot, wasmDir);

const errors = [];

function fail(message) {
    errors.push(message);
}

function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
const indexHtmlRaw = readFileSync(indexHtmlPath, 'utf8');
// Comments are not markup; ignore them for all structural checks below.
const indexHtml = indexHtmlRaw.replace(/<!--[\s\S]*?-->/g, '');

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

// 5. Content-Security-Policy and inline-code invariants (the page handles the PIN,
//    management key and bridge token, and GitHub Pages cannot set CSP headers).
function parseAttributes(tag) {
    const attrs = new Map();
    const body = tag.replace(/^<[a-zA-Z][\w-]*/, '').replace(/\/?>$/, '');
    for (const m of body.matchAll(/([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
        attrs.set(m[1].toLowerCase(), m[2] ?? m[3] ?? m[4] ?? '');
    }
    return attrs;
}

const startTags = [...indexHtml.matchAll(/<([a-zA-Z][\w-]*)\b[^>]*>/g)].map((m) => ({
    name: m[1].toLowerCase(),
    tag: m[0],
    index: m.index,
    attrs: parseAttributes(m[0]),
}));

const cspTags = startTags.filter(
    (t) => t.name === 'meta' && (t.attrs.get('http-equiv') || '').toLowerCase() === 'content-security-policy'
);
if (cspTags.length !== 1) {
    fail(`demo/index.html must contain exactly one <meta http-equiv="Content-Security-Policy"> (found ${cspTags.length})`);
} else {
    const cspTag = cspTags[0];
    const firstResource = startTags.find((t) => ['link', 'script', 'style', 'img'].includes(t.name));
    if (firstResource && firstResource.index < cspTag.index) {
        fail('The CSP <meta> must precede every <link>, <script>, <style> and <img> in demo/index.html');
    }
    const headEnd = indexHtml.search(/<\/head>/i);
    if (headEnd !== -1 && cspTag.index > headEnd) {
        fail('The CSP <meta> must be inside <head> (browsers ignore it in <body>)');
    }

    const directives = new Map();
    for (const part of (cspTag.attrs.get('content') || '').split(';')) {
        const [name, ...sources] = part.trim().split(/\s+/).filter(Boolean);
        if (name) directives.set(name.toLowerCase(), sources);
    }
    const requireExact = { 'object-src': "'none'", 'base-uri': "'none'", 'form-action': "'none'" };
    for (const [name, value] of Object.entries(requireExact)) {
        const sources = directives.get(name);
        if (!sources || sources.length !== 1 || sources[0] !== value) {
            fail(`CSP must set ${name} ${value}`);
        }
    }
    for (const name of ['default-src', 'script-src', 'style-src', 'connect-src']) {
        if (!directives.has(name)) fail(`CSP is missing the ${name} directive`);
    }
    const unsafe = new Set(["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", '*', 'data:', 'blob:', 'http:', 'https:']);
    for (const name of ['default-src', 'script-src', 'style-src']) {
        for (const source of directives.get(name) || []) {
            if (unsafe.has(source.toLowerCase())) {
                fail(`CSP ${name} must not allow ${source}`);
            }
        }
    }
    if (!(directives.get('script-src') || []).includes("'wasm-unsafe-eval'")) {
        fail("CSP script-src must include 'wasm-unsafe-eval' (required to compile the WASM module)");
    }
    if (directives.has('frame-ancestors')) {
        fail('CSP frame-ancestors is ignored in <meta> policies; do not rely on it');
    }
}

for (const t of startTags) {
    for (const [attr, value] of t.attrs) {
        if (/^on[a-z]+$/.test(attr)) {
            fail(`Inline event handler '${attr}' is blocked by the CSP: ${t.tag}`);
        }
        if (attr === 'style') {
            fail(`Inline style attribute is blocked by the CSP: ${t.tag}`);
        }
        if (['href', 'src', 'action', 'formaction'].includes(attr) && /^\s*javascript:/i.test(value)) {
            fail(`javascript: URL is blocked by the CSP: ${t.tag}`);
        }
    }
    if (t.name === 'style') {
        fail('Inline <style> elements are blocked by the CSP; use styles.css');
    }
}
for (const m of indexHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    if (!parseAttributes(`<script${m[1]}>`).has('src') || m[2].trim() !== '') {
        fail('Inline <script> content is blocked by the CSP; load scripts from files');
    }
}

// 6. demo/app.js invariants: no HTML injection sinks / eval, and every device call goes
//    through runDeviceTask (wasm-bindgen rejects calls on a busy YubiKeyDevice).
const forbiddenAppPatterns = [
    [/\.(?:innerHTML|outerHTML)\b/, 'innerHTML/outerHTML'],
    [/\binsertAdjacentHTML\s*\(/, 'insertAdjacentHTML()'],
    [/\bdocument\.write(?:ln)?\s*\(/, 'document.write()'],
    [/\beval\s*\(/, 'eval()'],
    [/\bnew\s+Function\s*\(/, 'new Function()'],
    [/\.setAttribute\(\s*['"](?:style|on[a-z]+)['"]/, 'setAttribute("style"/"on*")'],
    [/\bstate\.device\.[A-Za-z_$][\w$]*\s*\(/, 'direct state.device.<method>() calls (use runDeviceTask)'],
];
for (const [pattern, label] of forbiddenAppPatterns) {
    if (pattern.test(appJs)) {
        fail(`demo/app.js must not use ${label}`);
    }
}

// 7. Derive the WASM API that demo/app.js depends on, from app.js itself.
const wasmImport = appJs.match(
    /import\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*['"](\.\/wasm\/([\w-]+)\.js)['"]/
);
let wasmModuleName = null;
let defaultImport = null;
const namedImports = new Set();
if (!wasmImport) {
    fail("demo/app.js must import the WASM module from './wasm/<name>.js'");
} else {
    defaultImport = wasmImport[1] || null;
    wasmModuleName = wasmImport[4];
    for (const spec of (wasmImport[2] || '').split(',')) {
        const imported = spec.trim().split(/\s+as\s+/)[0];
        if (imported) namedImports.add(imported);
    }
    if (namedImports.size === 0) {
        fail('Could not parse the named imports of the WASM module in demo/app.js');
    }
}

// Every method invoked on a device object (`device.x(...)`) or on the class (`YubiKeyDevice.x(...)`).
const instanceMethods = new Set();
const staticMethods = new Set();
for (const m of appJs.matchAll(/\b(device|YubiKeyDevice)\.([A-Za-z_$][\w$]*)\s*\(/g)) {
    (m[1] === 'YubiKeyDevice' ? staticMethods : instanceMethods).add(m[2]);
}
if (instanceMethods.size === 0 || staticMethods.size === 0) {
    fail('Could not find any YubiKeyDevice calls in demo/app.js (expected `device.<method>(` and `YubiKeyDevice.<method>(`)');
}

// 7b. Without a WASM build: every name demo/app.js uses (named imports and
//     YubiKeyDevice methods) must be exported by crates/signer-wasm/src, either as
//     `#[wasm_bindgen(js_name = "...")]` or as a plain `#[wasm_bindgen]` item.
const wasmSrcDir = resolve(repoRoot, 'crates/signer-wasm/src');
const rustExports = new Set();
for (const file of readdirSync(wasmSrcDir).filter((f) => f.endsWith('.rs'))) {
    const source = readFileSync(resolve(wasmSrcDir, file), 'utf8');
    for (const m of source.matchAll(/#\[wasm_bindgen\(([^)\]]*)\)\]/g)) {
        const jsName = m[1].match(/\bjs_name\s*=\s*"([^"]+)"/);
        if (jsName) rustExports.add(jsName[1]);
    }
    for (const m of source.matchAll(/#\[wasm_bindgen\]\s*(?:#\[[^\]]*\]\s*)*pub\s+(?:async\s+)?(?:fn|struct)\s+([A-Za-z_]\w*)/g)) {
        rustExports.add(m[1]);
    }
}
for (const name of [...namedImports, ...staticMethods, ...instanceMethods]) {
    if (!rustExports.has(name)) {
        fail(`demo/app.js uses '${name}', which crates/signer-wasm/src does not export via #[wasm_bindgen]`);
    }
}

function exportedNames(source) {
    const names = new Set();
    for (const m of source.matchAll(/^export\s+(?:declare\s+)?(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)/gm)) {
        names.add(m[1]);
    }
    for (const m of source.matchAll(/^export\s*\{([^}]*)\}/gm)) {
        for (const spec of m[1].split(',')) {
            const parts = spec.trim().split(/\s+as\s+/);
            const exported = (parts[1] || parts[0]).trim();
            if (exported) names.add(exported);
        }
    }
    return names;
}

function hasDefaultExport(source) {
    return /^export\s+default\b/m.test(source) || /^export\s*\{[^}]*\bas\s+default\b[^}]*\}/m.test(source);
}

function classBody(source, className) {
    const start = source.search(new RegExp(`^(?:export\\s+)?(?:declare\\s+)?class\\s+${escapeRegExp(className)}\\b[^\\n]*\\{`, 'm'));
    if (start === -1) return null;
    const rest = source.slice(start);
    const end = rest.search(/^\}/m);
    return end === -1 ? rest : rest.slice(0, end);
}

function checkWasmApi(source, label) {
    const exports = exportedNames(source);
    if (defaultImport && !hasDefaultExport(source)) {
        fail(`${label} has no default export (demo/app.js imports it as '${defaultImport}')`);
    }
    for (const name of namedImports) {
        if (!exports.has(name)) {
            fail(`${label} is missing export '${name}' imported by demo/app.js`);
        }
    }
    const body = classBody(source, 'YubiKeyDevice');
    if (body === null) {
        fail(`${label} does not define class YubiKeyDevice`);
        return;
    }
    for (const name of staticMethods) {
        if (!new RegExp(`^[ \\t]+static\\s+(?:async\\s+)?${escapeRegExp(name)}\\s*\\(`, 'm').test(body)) {
            fail(`${label} is missing static method YubiKeyDevice.${name}() called by demo/app.js`);
        }
    }
    for (const name of instanceMethods) {
        if (!new RegExp(`^[ \\t]+(?:async\\s+)?${escapeRegExp(name)}\\s*\\(`, 'm').test(body)) {
            fail(`${label} is missing method YubiKeyDevice.prototype.${name}() called by demo/app.js`);
        }
    }
}

// 8. Optional: verify WASM build outputs against what demo/app.js uses
if (checkWasm) {
    if (!existsSync(wasmDir)) {
        fail(`WASM directory does not exist: ${wasmDirLabel}`);
    } else if (wasmModuleName) {
        const jsFile = `${wasmModuleName}.js`;
        const dtsFile = `${wasmModuleName}.d.ts`;
        for (const file of [jsFile, `${wasmModuleName}_bg.wasm`, dtsFile]) {
            if (!existsSync(resolve(wasmDir, file))) {
                fail(`Missing required WASM artifact: ${wasmDirLabel}/${file}`);
            }
        }
        for (const file of [jsFile, dtsFile]) {
            const fullPath = resolve(wasmDir, file);
            if (existsSync(fullPath)) {
                checkWasmApi(readFileSync(fullPath, 'utf8'), `${wasmDirLabel}/${file}`);
            }
        }
    }

    if (isNpmDist) {
        for (const file of ['.gitignore', 'package.json']) {
            if (existsSync(resolve(wasmDir, file))) {
                fail(`packages/npm/dist must not contain leftover wasm-pack file: ${file}`);
            }
        }

        // The npm tarball must ship the license texts. They are copied from the
        // repository root at build time (and git-ignored under packages/npm).
        const pkg = JSON.parse(readFileSync(resolve(npmPackageDir, 'package.json'), 'utf8'));
        const files = new Set(pkg.files || []);
        for (const license of ['LICENSE-MIT', 'LICENSE-APACHE']) {
            if (!files.has(license)) {
                fail(`packages/npm/package.json "files" must list ${license}`);
            }
            const copy = resolve(npmPackageDir, license);
            if (!existsSync(copy)) {
                fail(`Missing packages/npm/${license}: copy it from the repository root before packing (just npm-licenses)`);
            } else if (!readFileSync(copy).equals(readFileSync(resolve(repoRoot, license)))) {
                fail(`packages/npm/${license} differs from the repository root ${license}`);
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
        ? `OK: verified demo/app.js (${referencedIds.size} IDs), demo/index.html (CSP), and ${wasmDirLabel} ` +
              `(${namedImports.size} module exports, ${staticMethods.size + instanceMethods.size} YubiKeyDevice methods` +
              `${isNpmDist ? ', npm package layout' : ''}).`
        : `OK: verified demo/app.js (${referencedIds.size} IDs) and demo/index.html (CSP).`
);
