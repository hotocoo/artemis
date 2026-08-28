// Artemis e2e chaos harness: process management, ports, scopes, results.
// Everything here drives REAL built binaries against a REAL loopback lab.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '..');

// ---------- binary discovery ----------
// Matches the configuration the solution was built with (Debug locally, Release in CI),
// mirroring the C# LabFixture so the harness never runs a stale or missing binary.
function findBin(projectRel, dllName) {
  for (const cfg of ['Debug', 'Release']) {
    const p = path.join(ROOT, projectRel, 'bin', cfg, 'net10.0', dllName);
    if (fs.existsSync(p)) return p;
  }
  throw new Error('binary not found (build the solution first): ' + projectRel + '/' + dllName);
}
export const ARTEMIS_DLL = findBin('src/ACT.Cli', 'artemis.dll');
export const CONSOLE_DLL = findBin('src/ACT.Desktop', 'artemis-console.dll');
export const LAB_DLL = findBin('lab/ACT.Lab', 'ACT.Lab.dll');

// ---------- workdir / db ----------
export const WORK = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'artemis-e2e-'));
export const DB_PATH = path.join(WORK, 'artemis.db');
export const SHOTS = path.join(WORK, 'screenshots');
fs.mkdirSync(SHOTS, { recursive: true });
export function workfile(name) { return path.join(WORK, name); }
export function writeWork(name, content) { fs.writeFileSync(workfile(name), content); return workfile(name); }

// ---------- ports ----------
export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

// ---------- process management ----------
export function spawnProc(name, args, env = {}) {
  const proc = spawn('dotnet', args, {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = { out: '', err: '' };
  proc.stdout.on('data', d => { logs.out += d; });
  proc.stderr.on('data', d => { logs.err += d; });
  proc.logs = logs;
  proc.name = name;
  return proc;
}

export async function waitHttp(url, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.status < 500) return res.status;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 400));
  }
  throw new Error('service did not become healthy: ' + url);
}

export async function startLab() {
  const port = await freePort();
  const httpsPort = await freePort();
  const proc = spawnProc('lab', [LAB_DLL, '--port', String(port), '--https-port', String(httpsPort), '--lab-token', 'e2e-lab-token']);
  await waitHttp('http://127.0.0.1:' + port + '/healthz');
  return {
    proc, port, httpsPort,
    url: 'http://127.0.0.1:' + port,
    async kill() { killTree(proc); },
  };
}

export async function startConsole(dbPath, { openBrowser = false } = {}) {
  const port = await freePort();
  const proc = spawnProc('console', [CONSOLE_DLL], {
    ARTM_ACT__STORAGE__DATABASEPATH: dbPath,
    ARTM_ACT__UI__CONSOLEPORT: String(port),
    ARTM_ACT__UI__OPENBROWSERONSTART: openBrowser ? 'true' : 'false',
  });
  await waitHttp('http://127.0.0.1:' + port + '/health');
  return {
    proc, port,
    url: 'http://127.0.0.1:' + port,
    async kill() { killTree(proc); },
  };
}

export function killTree(proc) {
  if (!proc || proc.exitCode !== null) return;
  try {
    if (process.platform === 'darwin' || process.platform === 'linux') {
      const pid = proc.pid;
      spawn('pkill', ['-9', '-P', String(pid)]);
      proc.kill('SIGKILL');
    } else {
      spawn('taskkill', ['/pid', String(proc.pid), '/t', '/f']);
    }
  } catch { /* already gone */ }
}

// ---------- CLI ----------
export async function cli(args, { env = {}, timeoutMs = 120000 } = {}) {
  const start = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync('dotnet', [ARTEMIS_DLL, ...args], {
      env: { ...process.env, ...env },
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr, ms: Date.now() - start, json: tryParse(stdout) };
  } catch (e) {
    return {
      code: e.code ?? 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      ms: Date.now() - start,
      json: tryParse(e.stdout ?? ''),
      killed: e.killed,
    };
  }
}

function tryParse(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// The CLI env that pins the database so every invocation shares one store.
export function cliEnv() {
  return { ARTM_ACT__STORAGE__DATABASEPATH: DB_PATH };
}

// ---------- scopes ----------
export function makeScope(overrides = {}) {
  const base = {
    scopeId: crypto.randomUUID(),
    assessmentId: crypto.randomUUID(),
    operatorIdentity: 'e2e-chaos-operator',
    organization: 'artemis-e2e-chaos',
    targetType: 'Localhost',
    allowlistedTargets: ['localhost', '127.0.0.1'],
    excludedTargets: [],
    permittedProtocols: ['Tcp', 'Http', 'Https', 'Tls'],
    permittedPorts: [],
    requestsPerSecond: 25,
    concurrencyLimit: 4,
    maxRuntimeSeconds: 300,
    maxRequests: 1000,
    allowedCategories: ['Network', 'Tls', 'Http', 'Api', 'Authorization'],
    prohibitedCategories: [],
    emergencyStopEnabled: true,
    evidenceRetentionDays: 7,
    redactionPolicy: 'Standard',
    authorizationStatement: 'E2E chaos authorization for the local loopback lab.',
  };
  return { ...base, ...overrides };
}

export function writeScope(name, scope) {
  return writeWork(name, JSON.stringify(scope, null, 2));
}

// ---------- http helpers (for direct console API assertions) ----------
export async function httpGet(url) {
  const res = await fetch(url);
  const body = await res.text();
  return { status: res.status, headers: Object.fromEntries(res.headers), body };
}

export async function httpPostForm(url, fields) {
  const body = new URLSearchParams(fields).toString();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
  });
  const text = await res.text();
  return { status: res.status, location: res.headers.get('location'), body: text };
}

// ---------- results ----------
export const results = { passed: [], failed: [], checks: 0 };
export function check(name, cond, detail = '') {
  results.checks++;
  if (cond) {
    results.passed.push(name);
    console.log('  ok  ' + name);
  } else {
    results.failed.push({ name, detail: String(detail).slice(0, 400) });
    console.log('FAIL  ' + name + (detail ? ' :: ' + String(detail).slice(0, 400) : ''));
  }
  return !!cond;
}
export function section(title) { console.log('\n=== ' + title + ' ==='); }
export function summary() {
  console.log('\n=================================');
  console.log('E2E CHAOS SUMMARY');
  console.log('passed: ' + results.passed.length + '  failed: ' + results.failed.length + '  total: ' + results.checks);
  if (results.failed.length) {
    console.log('FAILED CHECKS:');
    for (const f of results.failed) console.log('  - ' + f.name + ' :: ' + f.detail);
  }
  console.log('workdir: ' + WORK);
  console.log('=================================');
  return results.failed.length === 0;
}

// ---------- playwright ----------
export async function withBrowser(fn) {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  page.shot = (name) => page.screenshot({ path: path.join(SHOTS, name), fullPage: true });
  try {
    return await fn(page);
  } finally {
    await browser.close();
  }
}
