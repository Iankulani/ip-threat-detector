#!/usr/bin/env ts-node
/**
 * Simple IP Threat Detector
 * -------------------------------------------------
 * Demo CLI that prompts for an IP/hostname, scans common TCP ports,
 * runs a few lightweight probes, and prints a human-readable risk report.
 *
 * NOTE: This is an educational tool — not a replacement for IDS/IPS.
 * No external dependencies; uses Node's built-in modules.
 */

import * as net from 'net';
import * as dns from 'dns';
import * as fs from 'fs';
import * as readline from 'readline';
import { promisify } from 'util';

// ---------- Types ----------

type PortInfo = { port: number; name: string };
type ScanResult = {
  target: string;
  ip: string;
  timestamp: string;
  openPorts: Array<PortInfo & { rttMs: number }>;
  closedPorts: Array<PortInfo & { reason: string }>;
  anomalies: string[];
  score: number; // 0-100
  verdict: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
};

// ---------- Constants ----------

const COMMON_PORTS: PortInfo[] = [
  { port: 21, name: 'ftp' },
  { port: 22, name: 'ssh' },
  { port: 23, name: 'telnet' },
  { port: 25, name: 'smtp' },
  { port: 53, name: 'dns(tcp)' },
  { port: 80, name: 'http' },
  { port: 110, name: 'pop3' },
  { port: 143, name: 'imap' },
  { port: 443, name: 'https' },
  { port: 3306, name: 'mysql' },
  { port: 3389, name: 'rdp' },
  { port: 5432, name: 'postgres' },
  { port: 6379, name: 'redis' },
  { port: 8080, name: 'http-alt' },
  { port: 27017, name: 'mongodb' },
];

const HISTORY_FILE = './threat-history.json';
const CONNECT_TIMEOUT_MS = 1000; // network-dependent

// ---------- Helpers ----------

const lookupAsync = promisify(dns.lookup);

function isValidIPorHost(input: string): boolean {
  if (!input || input.length > 253) return false;
  // Rough check: IPv4, IPv6, or hostname
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/; // simplistic
  const host = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.(?!-)[A-Za-z0-9-]{1,63})*\.?$/;
  return ipv4.test(input) || ipv6.test(input) || host.test(input);
}

async function resolveTarget(target: string): Promise<string> {
  try {
    const res = await lookupAsync(target);
    return res.address;
  } catch (e) {
    return target; // best effort; socket will fail if invalid
  }
}

function ms(): number {
  return Date.now();
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// Attempt a TCP connect and measure RTT.
function checkPort(ip: string, port: number): Promise<{ open: boolean; rtt: number; reason?: string }>{
  return new Promise((resolve) => {
    const start = ms();
    const socket = new net.Socket();
    let settled = false;

    const done = (result: { open: boolean; rtt: number; reason?: string }) => {
      if (!settled) {
        settled = true;
        try { socket.destroy(); } catch {}
        resolve(result);
      }
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      const rtt = ms() - start;
      done({ open: true, rtt });
    });
    socket.once('timeout', () => done({ open: false, rtt: ms() - start, reason: 'timeout' }));
    socket.once('error', (err) => done({ open: false, rtt: ms() - start, reason: err.code || 'error' }));

    socket.connect(port, ip);
  });
}

// Probes several times to gauge stability (rough DoS symptom heuristic)
async function latencyStabilityProbe(ip: string, port = 80, attempts = 5): Promise<{lossRate: number; avgRtt: number; jitter: number}> {
  const rtts: number[] = [];
  let failures = 0;
  for (let i = 0; i < attempts; i++) {
    const res = await checkPort(ip, port);
    if (res.open) rtts.push(res.rtt); else failures++;
    await sleep(120);
  }
  const avg = rtts.length ? rtts.reduce((a,b)=>a+b,0) / rtts.length : Infinity;
  const mean = avg || 0;
  const variance = rtts.length ? rtts.reduce((a,b)=>a+Math.pow(b-mean,2),0)/rtts.length : 0;
  const jitter = Math.sqrt(variance);
  const lossRate = attempts ? failures/attempts : 1;
  return { lossRate, avgRtt: isFinite(avg)?avg:CONNECT_TIMEOUT_MS, jitter };
}

function scoreFromFindings(openPorts: ScanResult['openPorts'], anomalies: string[]): number {
  let score = 0;
  // Base on exposure surface
  score += Math.min(openPorts.length * 6, 40);
  // Risky services weight
  const risky = ['telnet','ftp','rdp','redis','mongodb'];
  for (const p of openPorts) {
    if (risky.includes(p.name)) score += 10;
    if (p.port === 22 && p.rttMs < 40) score += 2; // accessible & close
  }
  // Anomalies bump
  score += Math.min(anomalies.length * 10, 40);
  return Math.max(0, Math.min(100, score));
}

function verdictFromScore(score: number): ScanResult['verdict'] {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MODERATE';
  return 'LOW';
}

function saveHistory(entry: ScanResult) {
  let arr: ScanResult[] = [];
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      arr = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')) as ScanResult[];
    }
  } catch {}
  arr.unshift(entry);
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(arr.slice(0, 50), null, 2));
}

function printBanner() {
  console.log('\n=== Simple IP Threat Detector ===');
  console.log('Educational CLI — scans common TCP ports and flags basic risks.');
  console.log('-----------------------------------------------\n');
}

function printReport(r: ScanResult) {
  console.log(`Target: ${r.target} -> ${r.ip}`);
  console.log(`When:   ${r.timestamp}`);
  console.log(`Score:  ${r.score}/100  Verdict: ${r.verdict}`);
  console.log('\nOpen Ports:');
  if (r.openPorts.length === 0) console.log('  none detected');
  else for (const p of r.openPorts) console.log(`  - ${p.port} (${p.name}) ~${p.rttMs}ms`);

  console.log('\nClosed/Filtered Samples:');
  for (const c of r.closedPorts.slice(0, 5)) console.log(`  - ${c.port} (${c.name}): ${c.reason}`);
  if (r.closedPorts.length > 5) console.log(`  ... and ${r.closedPorts.length - 5} more`);

  console.log('\nAnomalies:');
  if (!r.anomalies.length) console.log('  none');
  else r.anomalies.forEach(a => console.log('  - ' + a));

  console.log('\nRecommendations:');
  if (r.openPorts.length > 0) console.log('  • Restrict exposure: close or firewall unused services.');
  if (r.openPorts.some(p => ['telnet','ftp'].includes(p.name))) console.log('  • Replace legacy protocols (telnet/ftp) with secure alternatives (ssh/sftp).');
  if (r.verdict === 'HIGH' || r.verdict === 'CRITICAL') console.log('  • Consider WAF/DDoS protection and strict rate-limits.');
  console.log('  • Use real IDS/IPS (e.g., Suricata, Zeek) for continuous monitoring.');
}

// ---------- Main Workflow ----------

async function run() {
  printBanner();

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string) => new Promise<string>((res) => rl.question(q, res));

  let target = (await ask('Enter IP or hostname to scan: ')).trim();
  while (!isValidIPorHost(target)) {
    target = (await ask('Invalid input. Enter a valid IP/hostname: ')).trim();
  }

  console.log('Resolving target...');
  const ip = await resolveTarget(target);
  console.log(`Resolved to: ${ip}`);

  console.log('\nScanning common TCP ports (this may take a few seconds)...');
  const openPorts: ScanResult['openPorts'] = [];
  const closedPorts: ScanResult['closedPorts'] = [];

  for (const p of COMMON_PORTS) {
    const res = await checkPort(ip, p.port);
    if (res.open) openPorts.push({ ...p, rttMs: Math.round(res.rtt) });
    else closedPorts.push({ ...p, reason: res.reason || 'closed' });
  }

  // Sort open ports by number then RTT.
  openPorts.sort((a,b)=> a.port - b.port || a.rttMs - b.rttMs);

  console.log('Running stability probe...');
  const probe80 = await latencyStabilityProbe(ip, 80, 6);
  const probe443 = await latencyStabilityProbe(ip, 443, 6);

  const anomalies: string[] = [];
  const lossAvg = (probe80.lossRate + probe443.lossRate)/2;
  if (lossAvg > 0.5) anomalies.push(`High connection loss (~${Math.round(lossAvg*100)}%) — possible rate limiting or service stress.`);
  if (probe80.jitter > 150 || probe443.jitter > 150) anomalies.push('Elevated latency jitter — unstable path or overloaded service.');
  if (openPorts.length >= 8) anomalies.push('Large attack surface (many services exposed).');
  if (openPorts.some(p=>p.name==='telnet')) anomalies.push('Legacy service (telnet) exposed.');
  if (openPorts.some(p=>p.port===3389)) anomalies.push('RDP exposed — ensure strong auth and lockout policies.');

  const score = scoreFromFindings(openPorts, anomalies);
  const verdict = verdictFromScore(score);

  const result: ScanResult = {
    target,
    ip,
    timestamp: new Date().toISOString(),
    openPorts,
    closedPorts,
    anomalies,
    score,
    verdict,
  };

  saveHistory(result);
  rl.close();
  console.log('\n===== REPORT =====');
  printReport(result);
  console.log('\nHistory saved to', HISTORY_FILE);
}

run().catch((e) => {
  console.error('Unexpected error:', e?.message || e);
  process.exitCode = 1;
});
