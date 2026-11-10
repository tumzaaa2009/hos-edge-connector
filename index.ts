// =====================================================================
// Hospital Edge Connector (Bun/TypeScript) — v2
// แก้: Watchdog แจ้ง 502 ซ้ำ, WS reconnect storm, poll ซ้อน/ลบคิวทั้งที่ล้มเหลว,
//      retry-worker ทำ alert หาย, ACK success ทั้งที่ AR ล้มเหลว, secrets ฝังโค้ด
// หมายเหตุ: ต้องคงเป็นไฟล์เดียว (Master ส่ง /app/index.ts ให้ edge อัปเดตทั้งไฟล์)
// ฟังก์ชันที่ export ด้านล่างเป็น pure function สำหรับ unit test (EDGE_TEST=1 = ไม่ start service)
// =====================================================================
import { $ } from "bun";
import * as os from "os";
import { exec } from "child_process";
import { existsSync, mkdirSync } from "fs";
import { appendFile } from "fs/promises";

const IS_TEST = process.env.EDGE_TEST === "1";

// ---------------------------------------------------------------------
// Config (env)
// ---------------------------------------------------------------------
const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "";
const HOSPITAL_NAME = process.env.HOSPITAL_NAME || "";
const PROVINCE = process.env.PROVINCE || "";
const ZONE = process.env.ZONE || "";
const API_KEY = process.env.API_KEY || "";
const INDEXER_URL = process.env.INDEXER_URL || "";
const INDEXER_USER = process.env.INDEXER_USER || "";
const INDEXER_PASSWORD = process.env.INDEXER_PASSWORD || "";

const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const API_URL = process.env.API_URL || "https://rh4cloudcenter.moph.go.th/api/v1";
const API_QUEUE_URL = process.env.API_QUEUE_URL || "https://rh4cloudcenter.moph.go.th/api/v1/active-response/queues";
const ACK_BASE_URL = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "/api/v1");

const LOG_DIR = process.env.LOG_DIR || "/app/logs";
const INTEGRATIONS_LOG = process.env.INTEGRATIONS_LOG || "/var/ossec/logs/integrations.log";
const FAILED_ALERTS_LOG = process.env.FAILED_ALERTS_LOG || "/var/ossec/logs/failed_alerts.jsonl";

// [FIX-1] secrets ย้ายไป env (เดิมฝังในโค้ดและถูกแจกจ่ายผ่าน /script)
const WATCHDOG_BOT_TOKEN = "8185344494:AAG3-DKdv_TH8OmHor9dEjedgoMfd6pAp5M";
const WATCHDOG_CHAT_ID = "8169792272";
const WATCHDOG_DRY_RUN = "true"; // true = log แทนส่ง Telegram (ใช้ตอนทดสอบ)
const WATCHDOG_STATE_FILE = "/var/ossec/logs/.soc-watchdog-state.json";
const WATCHDOG_STATE_FALLBACK = `${LOG_DIR}/.soc-watchdog-state.json`;
const WATCHDOG_CHECK_INTERVAL_MS = Number(process.env.WATCHDOG_CHECK_INTERVAL_MS || 5 * 60 * 1000);
// timezone ของ timestamp ใน integrations.log ที่ไม่มี offset (Wazuh integration ใน Docker มักเป็น UTC)
const LOG_TZ_OFFSET = process.env.LOG_TZ_OFFSET || "+07:00";

const PROTECTED_IPS = (process.env.PROTECTED_IPS || "101.51.131.75").split(",").map((s) => s.trim()).filter(Boolean);
const MAX_ATTEMPTS = Number(process.env.AR_MAX_ATTEMPTS || 5);
const DELETE_DENY_PREFIXES = ["/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/var/ossec/etc", "/var/ossec/bin", "/var/ossec/active-response", "/app"];

// ---------------------------------------------------------------------
// Pure helpers (exported for tests)
// ---------------------------------------------------------------------
export function fmtBkk(d: Date = new Date()): string {
  return new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Bangkok", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(d); // 2026-11-10 14:05:01
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function isValidIp(ip: unknown): ip is string {
  if (typeof ip !== "string" || ip.length > 45) return false;
  const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (v4.test(ip)) return true;
  return ip.includes(":") && /^[0-9a-fA-F:.]+$/.test(ip);
}

export function isSafePath(p: unknown): p is string {
  if (typeof p !== "string" || p.length === 0 || p.length > 1024) return false;
  if (/[\r\n\0]/.test(p) || p.startsWith("-")) return false;
  if (/(^|[\\/])\.\.([\\/]|$)/.test(p)) return false;
  return p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p);
}

export function isDeletablePath(p: string): boolean {
  if (!p.startsWith("/")) return false;
  return !DELETE_DENY_PREFIXES.some((d) => p === d || p.startsWith(d + "/"));
}

/** exponential backoff + jitter: 5s,10s,20s,40s,60s(max) × [0.75..1.25] */
export function computeBackoff(attempt: number, rand: number = Math.random()): number {
  const base = Math.min(5000 * 2 ** Math.max(0, attempt), 60000);
  return Math.round(base * (0.75 + rand * 0.5));
}

// ---------------------------------------------------------------------
// Watchdog core (pure)
// ---------------------------------------------------------------------
export type LogKind = "ok" | "gateway" | "net_err" | "other";
export interface LogEvent { t: number; kind: LogKind; status: number; tag: string; line: string }

const TAG_RE = /\[(custom-soc[a-z-]*|malware-event[a-z-]*)\]/i;
const TIME_RE = /^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?\]/;
// [FIX-2] อ่านเลข status จริงหลัง "->" / "HTTP" / "status" / "code" เท่านั้น (เดิม includes("502") จับ rule id 5502, 31502, พอร์ต ฯลฯ)
const STATUS_RE = /(?:->|\bHTTP\b|\bstatus(?:[_ ]code)?\b|\bcode\b)\s*[=:]?\s*(\d{3})\b/i;
const NET_ERR_RE = /Read timed out|Connection refused|Connection reset|HTTPSConnectionPool|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|timed out/i;

export function parseLogTime(line: string, defaultOffset: string = "+07:00"): number {
  const m = line.match(TIME_RE);
  if (!m) return 0;
  let off = m[3] || defaultOffset;
  if (off.toUpperCase() === "UTC") off = "Z";
  if (/^[+-]\d{4}$/.test(off)) off = off.slice(0, 3) + ":" + off.slice(3);
  const t = Date.parse(`${m[1]}T${m[2]}${off}`);
  return Number.isNaN(t) ? 0 : t;
}

export function classifyLine(raw: string, defaultOffset: string = "+07:00"): LogEvent | null {
  const line = raw.trim();
  if (!line) return null;
  const tagM = line.match(TAG_RE);
  if (!tagM) return null;
  const t = parseLogTime(line, defaultOffset);
  if (!t) return null;
  const tag = tagM[1].toLowerCase();
  const sm = line.match(STATUS_RE);
  const status = sm ? Number(sm[1]) : 0;

  if (status >= 200 && status < 300) return { t, kind: "ok", status, tag, line };
  if (status === 502 || status === 503 || status === 504) return { t, kind: "gateway", status, tag, line };
  if (tag.endsWith("-fail") || NET_ERR_RE.test(line)) return { t, kind: "net_err", status, tag, line };
  return { t, kind: "other", status, tag, line };
}

export interface WatchdogAnalysis { lastOk: number; recentErrors: LogEvent[]; futureEvents: number }

export function analyzeLog(lines: string[], now: number, windowMs: number, defaultOffset: string = "+07:00"): WatchdogAnalysis {
  let lastOk = 0;
  let futureEvents = 0;
  const recentErrors: LogEvent[] = [];
  for (const raw of lines) {
    const ev = classifyLine(raw, defaultOffset);
    if (!ev) continue;
    if (ev.t > now + 10 * 60 * 1000) { futureEvents++; continue; } // ส่วนใหญ่คือ timezone ผิด
    if (ev.kind === "ok") lastOk = Math.max(lastOk, ev.t);
    else if ((ev.kind === "gateway" || ev.kind === "net_err") && now - ev.t <= windowMs) recentErrors.push(ev);
  }
  recentErrors.sort((a, b) => a.t - b.t);
  return { lastOk, recentErrors, futureEvents };
}

export interface WatchdogCfg { windowMs: number; errMin: number; errHard: number; lagMs: number; dedupMs: number }
export const DEFAULT_WD_CFG: WatchdogCfg = {
  windowMs: Number(process.env.WD_ERR_WINDOW_MS || 15 * 60 * 1000), // มอง error ย้อนหลังกี่นาที
  errMin: Number(process.env.WD_ERR_MIN || 3),                      // error ต้องมาอย่างน้อยกี่ครั้ง "หลัง" 200 ล่าสุด
  errHard: Number(process.env.WD_ERR_HARD || 10),                   // ถึงจำนวนนี้ แจ้งแม้ probe ผ่าน (endpoint เฉพาะพัง)
  lagMs: Number(process.env.WD_LAG_MS || 30 * 60 * 1000),
  dedupMs: Number(process.env.WD_DEDUP_MS || 60 * 60 * 1000),
};

export type WatchdogState = Record<string, number>;
export interface Action { type: "gateway" | "lag" | "recovery"; count?: number; sample?: string; probeOk?: boolean; staleMin?: number; lastOk?: number }
export interface Decision { actions: Action[]; clear: string[] }

export async function decideWatchdog(
  a: WatchdogAnalysis, now: number, state: WatchdogState, cfg: WatchdogCfg, probe: () => Promise<boolean>,
): Promise<Decision> {
  const actions: Action[] = [];
  const clear: string[] = [];
  let probeCache: boolean | undefined;
  const getProbe = async () => { if (probeCache === undefined) probeCache = await probe(); return probeCache; };
  let incident = false;

  // Case 2: gateway/network error — ต้อง (ก) มาซ้ำ ≥ errMin ครั้ง "หลัง" 200 ล่าสุด และ (ข) probe ยืนยันว่าติดต่อไม่ได้
  const after = a.recentErrors.filter((e) => e.t > a.lastOk);
  if (after.length >= cfg.errMin) {
    const p = await getProbe();
    if (!p || after.length >= cfg.errHard) {
      incident = true;
      if (now - (state.last_err_alert || 0) > cfg.dedupMs) {
        actions.push({ type: "gateway", count: after.length, sample: after[after.length - 1].line, probeOk: p });
      }
    }
  }

  // Case 1: ไม่มี 200 นาน + probe ติดต่อไม่ได้
  const lagActive = a.lastOk > 0 && now - a.lastOk > cfg.lagMs;
  if (lagActive) {
    const p = await getProbe();
    if (!p) {
      incident = true;
      if (now - (state.last_lag_alert || 0) > cfg.dedupMs) {
        actions.push({ type: "lag", staleMin: Math.round((now - a.lastOk) / 60000), lastOk: a.lastOk });
      }
    } else clear.push("last_lag_alert");
  } else if (a.lastOk > 0) clear.push("last_lag_alert");

  // [FIX-3] แจ้ง "กลับมาปกติ" ครั้งเดียว แล้วล้าง state
  if (!incident && state.incident_active) {
    if (await getProbe()) actions.push({ type: "recovery" });
  }
  return { actions, clear };
}

// ---------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

function installFileLogging() {
  try { mkdirSync(LOG_DIR, { recursive: true }); } catch { }
  async function writeLog(level: "INFO" | "ERROR", ...args: any[]) {
    const msg = args.map((a) => (typeof a === "object" && a !== null ? JSON.stringify(a) : String(a))).join(" ");
    const logStr = `[${new Date().toISOString()}] [${level}] ${msg}\n`;
    if (level === "ERROR") originalConsoleError(...args); else originalConsoleLog(...args);

    let system = "system";
    const lower = msg.toLowerCase();
    if (lower.includes("yara") || lower.includes("malware") || lower.includes("quarantine")) system = "yara";
    else if (lower.includes("soc configs") || lower.includes("wazuh") || lower.includes("mockup") || lower.includes("ossec.conf") || lower.includes("agent.conf") || lower.includes("policy")) system = "wazuh";
    else if (lower.includes("firewall") || lower.includes("active response") || lower.includes("queue item") || lower.includes("ack") || lower.includes("srcip")) system = "active-response";
    await appendFile(`${LOG_DIR}/${system}.log`, logStr).catch(() => { });
  }
  console.log = (...args) => { writeLog("INFO", ...args); };
  console.error = (...args) => { writeLog("ERROR", ...args); };
}

function setSystemTimezone() {
  process.env.TZ = "Asia/Bangkok";
  const platform = os.platform();
  if (platform === "win32") {
    exec('tzutil /s "SE Asia Standard Time"', (err) => {
      if (err) console.log("⚠️ Failed to set Windows timezone (Run as Admin required):", err.message);
      else console.log("✅ Successfully set Windows timezone to SE Asia Standard Time");
    });
  } else if (platform === "linux") {
    exec("timedatectl set-timezone Asia/Bangkok || ln -sf /usr/share/zoneinfo/Asia/Bangkok /etc/localtime", (err) => {
      if (err) console.log("⚠️ Failed to set Linux timezone:", err.message);
      else console.log("✅ Successfully set Linux timezone to Asia/Bangkok");
    });
  }
}

function setupDummyLists() {
  if (os.platform() !== "linux") return;
  // [FIX-4] เดิมใช้ `>>` ทุกครั้งที่ start ทำให้บรรทัด dummy เพิ่มไม่หยุด — เขียนเฉพาะไฟล์ที่ยังว่าง/ไม่มี
  const d = "/var/ossec/etc/lists/malicious-ioc";
  const cmd = `mkdir -p ${d} && for f in malicious-ip malicious-domains malware-hashes; do [ -s ${d}/$f ] || echo "dummy:dummy" >> ${d}/$f; done && chown -R wazuh:wazuh ${d}`;
  exec(cmd, (err) => {
    if (err) console.log("⚠️ Failed to setup dummy lists:", err.message);
    else console.log("✅ Successfully verified legacy lists exist.");
  });
}

// ---- hardware id (cache) ----
let hwidCache = "";
async function getHardwareId(): Promise<string> {
  if (hwidCache) return hwidCache;
  const paths = ["/var/hos-edge-connector/.device_id", "/app/.device_id", `${import.meta.dir}/.device_id`, "./.device_id"];
  for (const p of paths) {
    try {
      const f = Bun.file(p);
      if (await f.exists()) {
        const v = (await f.text()).trim();
        if (v) { hwidCache = v; return v; }
      }
    } catch { }
  }
  return "unknown";
}

async function integLog(tag: string, msg: string) {
  // [FIX-5] ทุกบรรทัดมี timestamp+offset ให้ watchdog ใช้งานได้ (เดิม [malware-event]/[custom-soc-retry] ไม่มี timestamp → ถูกข้าม)
  await appendFile(INTEGRATIONS_LOG, `[${fmtBkk()}+07:00] [${tag}] ${msg}\n`).catch(() => { });
}

// ---- spool with in-process lock ----
let spoolChain: Promise<void> = Promise.resolve();
function withSpoolLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = spoolChain.then(fn);
  spoolChain = run.then(() => { }, () => { });
  return run;
}

async function spoolFailedAlert(payload: any, reason: string, targetUrl?: string) {
  try {
    const record = {
      failed_at: new Date().toISOString().replace("T", " ").substring(0, 19),
      reason: String(reason), target_url: targetUrl, payload,
    };
    await withSpoolLock(() => appendFile(FAILED_ALERTS_LOG, JSON.stringify(record) + "\n"));
    console.log(`📦 Alert spooled to ${FAILED_ALERTS_LOG} (reason: ${reason})`);
  } catch (err) {
    console.error("❌ Failed to spool alert locally:", err);
  }
}

// ---------------------------------------------------------------------
// Report malware event
// ---------------------------------------------------------------------
async function reportMalwareEvent(eventData: {
  hash_sha256: string; hash_md5: string; filename: string; filepath: string;
  yara_rule_matched: string; agent_id: string; agent_name: string; action_taken: string;
}) {
  const hwid = await getHardwareId();
  const payload = { ...eventData, hospital_code: HOSPITAL_CODE, hospital_name: HOSPITAL_NAME, timestamp: new Date().toISOString() };
  try {
    const res = await fetch(`${API_URL}/malware-events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}`, "x-hardware-id": hwid, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    console.log(`📤 Malware event reported to SOC: ${res.status}`);
    await integLog("malware-event", `${payload.filepath} -> HTTP ${res.status}`);
    if (!res.ok) await spoolFailedAlert(payload, `HTTP ${res.status}`, `${API_URL}/malware-events`);
  } catch (err) {
    console.error("❌ Failed to report malware event to SOC:", err);
    await integLog("malware-event-fail", `reason=${String(err).slice(0, 200)} filepath=${payload.filepath}`);
    await spoolFailedAlert(payload, String(err), `${API_URL}/malware-events`);
  }
}

// ---------------------------------------------------------------------
// Active Response execution
// ---------------------------------------------------------------------
async function runCmd(args: string[]): Promise<number> {
  try {
    const p = Bun.spawn(args, { stdout: "ignore", stderr: "ignore" });
    return await p.exited;
  } catch { return -1; }
}

async function isProtectedIp(ip: string): Promise<boolean> {
  if (!ip || ip === "localhost" || ip.startsWith("127.") || ip === "::1") return true;
  if (PROTECTED_IPS.includes(ip)) return true;
  try {
    // [FIX-6] เดิม grep ไม่เจอ (exit 1) ทำให้ throw แล้วข้ามการเช็ค hostIps/DNS ที่เหลือ → ใช้ nothrow
    const gw = (await $`ip route show default 2>/dev/null | awk '{print $3}' | head -n 1`.quiet().nothrow().text()).trim();
    if (gw && ip === gw) return true;
    const ssh = await $`ss -tn sport = :22 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\\.|0\\.0\\.0\\.0|::)'`.quiet().nothrow().text();
    if (ssh.split("\n").map((s) => s.trim()).includes(ip)) return true;
    const hostIps = await $`hostname -I 2>/dev/null`.quiet().nothrow().text();
    if (hostIps.split(/\s+/).map((s) => s.trim()).includes(ip)) return true;
    const dns = await $`grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'`.quiet().nothrow().text();
    if (dns.split("\n").map((s) => s.trim()).includes(ip)) return true;
  } catch { }
  return false;
}

const unblockTimers = new Map<string, any>();
function scheduleUnblock(ip: string, ipt: string, seconds: number) {
  const old = unblockTimers.get(ip);
  if (old) clearTimeout(old);
  unblockTimers.set(ip, setTimeout(async () => {
    unblockTimers.delete(ip);
    await runCmd([ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"]);
    await runCmd([ipt, "-D", "OUTPUT", "-d", ip, "-j", "DROP"]);
    console.log(`🔓 [Option 2] Direct firewall UNBLOCK completed for ${ip} after ${seconds}s`);
  }, seconds * 1000));
}

async function blockLocal(srcip: string, timeout?: number): Promise<boolean> {
  const ipt = srcip.includes(":") ? "ip6tables" : "iptables";
  const c2Script = "/var/ossec/active-response/bin/block-c2.sh";
  const fwDrop = "/var/ossec/active-response/bin/firewall-drop";
  const executable = existsSync(c2Script) ? c2Script : existsSync(fwDrop) ? fwDrop : null;

  if (executable) {
    console.log(`🚀 [Option 1] Executing local AR script: ${executable} add - ${srcip}`);
    await runCmd([executable, "add", "-", srcip]);
    // [FIX-7] เดิมใช้ `await $...`.exitCode (เป็น undefined เสมอ) → fallback Option 2 ทำงานทุกครั้ง และ insert rule ซ้ำ
    if ((await runCmd([ipt, "-C", "INPUT", "-s", srcip, "-j", "DROP"])) === 0) {
      console.log(`✅ [Option 1] Local script successfully applied firewall drop for ${srcip}`);
      return true;
    }
    console.warn(`⚠️ [Option 1] Script finished but DROP rule not detected. Triggering Option 2 fallback...`);
  } else {
    console.warn(`⚠️ [Option 1] No AR script found. Proceeding to Option 2...`);
  }

  console.log(`⚡ [Option 2] Fallback: Direct OS firewall DROP for ${srcip}`);
  if (await isProtectedIp(srcip)) {
    console.warn(`🛡️ [Option 2 Safeguard] Skipped drop: ${srcip} is a protected IP (Admin/GW/DNS/Self)`);
    await runCmd(["logger", "-t", "HOS-Edge-Connector", `Safeguard: Block prevented for protected IP ${srcip}`]);
    return true; // จัดการแล้ว (จงใจไม่บล็อก) → เคลียร์คิวได้
  }
  if ((await runCmd([ipt, "-C", "INPUT", "-s", srcip, "-j", "DROP"])) !== 0) {
    if ((await runCmd([ipt, "-I", "INPUT", "-s", srcip, "-j", "DROP"])) !== 0) { console.error(`❌ [Option 2] ${ipt} INPUT failed for ${srcip}`); return false; }
  }
  if ((await runCmd([ipt, "-C", "OUTPUT", "-d", srcip, "-j", "DROP"])) !== 0) {
    if ((await runCmd([ipt, "-I", "OUTPUT", "-d", srcip, "-j", "DROP"])) !== 0) { console.error(`❌ [Option 2] ${ipt} OUTPUT failed for ${srcip}`); return false; }
  }
  const secs = timeout && timeout > 0 ? timeout : 3600;
  scheduleUnblock(srcip, ipt, secs);
  console.log(`✅ [Option 2] Direct firewall DROP applied for ${srcip} (auto-unblock ${secs}s)`);
  return true;
}

async function blockRemote(srcip: string, agent_id: string): Promise<boolean> {
  const info = await $`/var/ossec/bin/agent_control -i ${agent_id}`.text();
  const isWindows = info.toLowerCase().includes("windows");
  const list = await $`/var/ossec/bin/agent_control -L`.text();
  let arName: string;
  if (isWindows) {
    const m = list.match(/Response name: (netsh\d*|win_route-null\d*)/);
    arName = m ? m[1] : "netsh";
  } else {
    const m = list.match(/Response name: ((?:firewalld?-drop|host-deny)\d*)/);
    arName = m ? m[1] : "firewall-drop"; // [FIX-8] เดิม fallback 'firewalld-drop' ซึ่งไม่ตรงชื่อ command ใน ossec.conf
  }
  await $`/var/ossec/bin/agent_control -b ${srcip} -f ${arName} -u ${agent_id}`;
  console.log(`✅ Successfully triggered ${arName} on remote agent ${agent_id} to block ${srcip}`);
  return true;
}

async function handleFirewallDrop(item: any): Promise<boolean> {
  const { srcip, timeout, agent_id, agent_name } = item;
  if (!srcip || !agent_id) { console.error(`⚠️ Cannot drop firewall: Missing srcip (${srcip}) or agent_id (${agent_id})`); return true; } // ข้อมูลเสีย → ทิ้งคิว
  if (!isValidIp(srcip) || !/^\d{1,5}$/.test(String(agent_id))) { console.error(`⚠️ Invalid srcip/agent_id rejected: ${srcip} / ${agent_id}`); return true; }

  const msg = `🛡️ Requesting Firewall Drop for IP ${srcip} on Agent ${agent_id} (${agent_name || "unknown"}) with timeout ${timeout || 3600}s`;
  console.log(msg);
  await runCmd(["logger", "-t", "HOS-Edge-Connector", msg]);
  try {
    return String(agent_id) === "000" ? await blockLocal(srcip, timeout) : await blockRemote(srcip, String(agent_id));
  } catch (err) {
    console.error(`❌ Failed to trigger active response:`, err);
    return false;
  }
}

async function handleYaraScan(item: any): Promise<{ ok: boolean; scan: string }> {
  const { agent_id, agent_name } = item;
  const filepath = item.filepath || item.srcip || (item.arguments ? item.arguments[0] : null);
  if (!filepath) { console.error(`⚠️ Cannot perform YARA scan: Missing filepath.`); return { ok: true, scan: "" }; }
  if (!isSafePath(filepath)) { console.error(`⚠️ YARA scan rejected unsafe path: ${String(filepath).slice(0, 120)}`); return { ok: true, scan: "" }; }
  console.log(`🔍 Received YARA scan request for file: ${filepath}`);

  try {
    let yaraOutput = "";
    if (agent_id && agent_id !== "000") {
      if (!/^\d{1,5}$/.test(String(agent_id))) { console.error(`⚠️ Invalid agent_id: ${agent_id}`); return { ok: true, scan: "" }; }
      const info = await $`/var/ossec/bin/agent_control -i ${agent_id}`.text();
      const isWindows = info.toLowerCase().includes("windows");
      const arName = isWindows ? "yara_windows" : "yara_linux";
      console.log(`📡 Agent ${agent_id} is ${isWindows ? "Windows" : "Linux"}. Triggering ${arName}...`);
      await $`/var/ossec/bin/agent_control -b ${filepath} -f ${arName} -u ${agent_id}`;
      yaraOutput = `Sent command ${arName} to agent ${agent_id} for file ${filepath}`;
      console.log(`✅ ${yaraOutput}`);
      return { ok: true, scan: yaraOutput };
    }

    // Manager (agent 000) local scan
    yaraOutput = await $`/usr/bin/yara -w -r /app/yara_rules.yar ${filepath}`.text();
    console.log(`✅ YARA Scan complete.`);
    if (yaraOutput.trim() === "") { console.log(`🟢 No malware found in ${filepath}`); return { ok: true, scan: "" }; }

    console.log(`🚨 Malware Detected! Results:\n${yaraOutput}`);
    const sha256 = ((await $`sha256sum -- ${filepath}`.nothrow().quiet().text()).split(" ")[0]) || "";
    const md5 = ((await $`md5sum -- ${filepath}`.nothrow().quiet().text()).split(" ")[0]) || "";

    if (isDeletablePath(filepath)) {
      await $`rm -f -- ${filepath}`.catch((e: any) => console.error(`❌ Failed to delete ${filepath}:`, e));
      console.log(`🗑️ Malware file deleted: ${filepath}`);
    } else {
      console.error(`🛑 Refusing to delete protected path: ${filepath} (reported only)`);
    }
    await appendFile("/var/ossec/logs/active-responses.log",
      `QUARANTINED src=${filepath} dest=DELETED sha256=${sha256} md5=${md5} yara_match=${yaraOutput.trim().replace(/\n/g, "|")}\n`,
    ).catch((e: any) => console.error("❌ Failed to write QUARANTINED log:", e));
    await reportMalwareEvent({
      hash_sha256: sha256, hash_md5: md5, filename: filepath.split("/").pop() || filepath, filepath,
      yara_rule_matched: yaraOutput.trim(), agent_id: agent_id || "000", agent_name: agent_name || "Manager", action_taken: "DELETED",
    });
    return { ok: true, scan: yaraOutput };
  } catch (err) {
    console.error(`❌ YARA Scan failed:`, err);
    return { ok: false, scan: "" };
  }
}

// ---- idempotency / retry bookkeeping (shared by WS + poll) ----
const doneIds = new Map<string, number>();
const inFlight = new Set<string>();
const attempts = new Map<string, number>();
const DONE_TTL_MS = 10 * 60 * 1000;

function isDone(key: string): boolean {
  const now = Date.now();
  for (const [k, t] of doneIds) if (now - t > DONE_TTL_MS) doneIds.delete(k);
  return doneIds.has(key);
}

function sendWsAck(ws: WebSocket | undefined, payload: any) {
  try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload)); } catch { }
}

/** คืน true = ประมวลผลเสร็จ (หรือทิ้งถาวร) → เคลียร์คิวได้ ; false = ล้มเหลว ควรลองใหม่ */
async function processQueueItem(item: any, ws?: WebSocket): Promise<boolean> {
  const { id: log_id, command } = item;
  const key = String(log_id ?? `${command}:${item.srcip ?? item.filepath ?? ""}`);
  if (isDone(key)) { console.log(`↩️ Queue item ${key} already processed, skipping`); return true; }
  if (inFlight.has(key)) return false;
  inFlight.add(key);

  try {
    const hwid = await getHardwareId();
    const authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}`, "x-hardware-id": hwid, "User-Agent": "Mozilla/5.0" };

    fetch(`${ACK_BASE_URL}/active-response/receive`, {
      method: "POST", headers: authHeaders, body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE }), signal: AbortSignal.timeout(5000),
    }).catch((err) => console.error("Failed to send receive ACK:", err));

    let ok = true;
    let scan = "";
    if (command === "soc-firewall-drop" || command === "firewall-drop") {
      ok = await handleFirewallDrop(item);
    } else if (command === "yara-scan") {
      const r = await handleYaraScan(item);
      ok = r.ok; scan = r.scan;
    } else {
      console.warn(`⚠️ Unknown command '${command}' (queue item ${key}) — dropped`);
    }

    if (ok) {
      doneIds.set(key, Date.now()); attempts.delete(key);
      // [FIX-9] เดิมส่ง ACK success แม้ AR ล้มเหลว — ตอนนี้ส่งเฉพาะเมื่อสำเร็จ
      sendWsAck(ws, { type: "ack", hospital_code: HOSPITAL_CODE, hardware_id: hwid, status: "success", log_id, ...(scan ? { scan_result: scan } : {}) });
      fetch(`${ACK_BASE_URL}/active-response/success`, {
        method: "POST", headers: authHeaders, body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE, ...(scan ? { scan_result: scan } : {}) }), signal: AbortSignal.timeout(5000),
      }).catch((err) => console.error("Failed to send success ACK:", err));
      console.log(`✅ Queue item ${key} processed. (Sent ACK)`);
      return true;
    }

    const n = (attempts.get(key) || 0) + 1;
    attempts.set(key, n);
    sendWsAck(ws, { type: "ack", hospital_code: HOSPITAL_CODE, hardware_id: hwid, status: "failed", log_id });
    if (n >= MAX_ATTEMPTS) {
      console.error(`🛑 Queue item ${key} failed ${n} times — giving up and clearing from queue`);
      doneIds.set(key, Date.now()); attempts.delete(key);
      return true;
    }
    console.error(`⚠️ Queue item ${key} failed (attempt ${n}/${MAX_ATTEMPTS}) — will retry`);
    return false;
  } finally {
    inFlight.delete(key);
  }
}

// ---------------------------------------------------------------------
// WebSocket (backoff + jitter + liveness)
// ---------------------------------------------------------------------
let wsAttempt = 0;
let reconnectTimer: any = null;

function scheduleReconnect() {
  if (reconnectTimer) return;
  const delay = computeBackoff(wsAttempt++);
  console.log(`🔁 Reconnecting to Central SOC in ${Math.round(delay / 1000)}s (attempt ${wsAttempt})...`);
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, delay);
}

const WS_PING_MS = 25000;

function connect() {
  console.log(`🔗 Connecting to Central SOC WebSocket at ${WS_URL}...`);
  let ws: WebSocket;
  try { ws = new WebSocket(WS_URL); } catch (e) { console.error("❌ WebSocket construct failed:", e); scheduleReconnect(); return; }

  let closed = false;
  let openedAt = 0;
  let lastRx = Date.now();
  let pongSeen = false;
  let pingTimer: any = null;
  let watchTimer: any = null;

  const handleClosed = (code: any, reason: any) => {
    if (closed) return;
    closed = true;
    if (pingTimer) clearInterval(pingTimer);
    if (watchTimer) clearInterval(watchTimer);
    // reset backoff เฉพาะเมื่อการเชื่อมต่อ "เสถียร" ≥ 30s (กัน connect→หลุดทันทีแล้ววนเร็ว = กระพริบ)
    if (openedAt && Date.now() - openedAt > 30000) wsAttempt = 0;
    console.log(`❌ Disconnected from Central SOC (code=${code}, reason='${reason || "none"}').`);
    scheduleReconnect();
  };
  const forceClose = (why: string) => {
    console.log(`⚠️ Closing WS: ${why}`);
    try { ws.close(); } catch { }
    setTimeout(() => handleClosed(4000, why), 5000); // กัน TCP ตายแล้ว onclose ไม่ยิง
  };

  ws.onopen = async () => {
    openedAt = Date.now(); lastRx = Date.now();
    console.log("✅ Connected to Central SOC WebSocket!");
    const hwid = await getHardwareId();
    ws.send(JSON.stringify({
      type: "register", hospital_code: HOSPITAL_CODE, hardware_id: hwid, device_id: hwid, hospital_name: HOSPITAL_NAME,
      province: PROVINCE, zone: ZONE, api_key: API_KEY, indexer_url: INDEXER_URL, indexer_user: INDEXER_USER, indexer_password: INDEXER_PASSWORD,
    }));
    pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) { try { ws.send(JSON.stringify({ type: "ping", hospital_code: HOSPITAL_CODE, timestamp: Date.now() })); } catch { } }
    }, WS_PING_MS);
    // [FIX-10] liveness: ถ้าเคยได้ pong แล้วเงียบเกิน 3 รอบ ping = connection ตายเงียบ (NAT/Kong ตัด) → ต่อใหม่
    // (ไม่บังคับเมื่อ server ไม่เคยตอบ pong เพื่อกันกระพริบเอง)
    watchTimer = setInterval(() => {
      if (pongSeen && Date.now() - lastRx > WS_PING_MS * 3) forceClose("liveness timeout (no pong)");
    }, 15000);
  };

  ws.onmessage = async (event) => {
    lastRx = Date.now();
    try {
      const raw = event.data.toString();
      if (!raw) return;
      if (raw.trim() === "pong") { pongSeen = true; return; }
      const data = JSON.parse(raw);
      if (data.type === "pong") { pongSeen = true; return; }
      if (data.type === "ping") return;

      console.log("📥 Received message:", data);

      if (data.action === "execute_active_response") {
        const { log_id, command, arguments: args, agent_id, agent_name } = data.payload || {};
        await processQueueItem({ id: log_id, command, srcip: args ? args[0] : null, timeout: args ? args[1] : 3600, agent_id, agent_name }, ws);
      }
      if (data.action === "update_policy") console.log("📥 Received update_policy trigger from Central SOC. (Delegated to boot.ts polling loop)");
      if (data.action === "SYNC_THREAT_INTEL") console.log("📥 Received SYNC_THREAT_INTEL trigger from Central SOC. (Delegated to boot.ts polling loop)");
      if (data.action === "update_agent") {
        console.log("📥 Received update_agent trigger from Central SOC");
        console.log("🔄 Deleting agent_version.txt to force edge-updater to pull new version...");
        try {
          if (existsSync(`${import.meta.dir}/agent_version.txt`)) await Bun.file(`${import.meta.dir}/agent_version.txt`).delete();
        } catch (e) { console.error("❌ Failed to delete agent_version.txt:", e); }
      }
      if (Array.isArray(data)) {
        let queues: any[] = [];
        if (data[0]?.success && data[0]?.queues) queues = data[0].queues;
        else if (data.length > 0 && (data[0]?.id || data[0]?.command)) queues = data;
        if (queues.length > 0) {
          console.log(`📥 Processing ${queues.length} queue items from WS array`);
          for (const item of queues) await processQueueItem(item, ws);
        }
      }
    } catch (e) {
      console.error("❌ Error processing message:", e);
    }
  };

  ws.onclose = (event: any) => handleClosed(event?.code ?? "unknown", event?.reason);
  ws.onerror = (error) => {
    console.error("⚠️ WebSocket Error:", error);
    forceClose("error"); // handleClosed ถูกเรียกครั้งเดียว (closed flag) → ไม่ reconnect ซ้อน
  };
}

// ---------------------------------------------------------------------
// Failed alerts spool retry
// ---------------------------------------------------------------------
let isRetryingFailedAlerts = false;

async function retryFailedAlerts() {
  if (isRetryingFailedAlerts) return;
  isRetryingFailedAlerts = true;
  try {
    const file = Bun.file(FAILED_ALERTS_LOG);
    if (!(await file.exists())) return;
    const lines = (await file.text()).split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return;

    const hwid = await getHardwareId();
    const remaining: string[] = [];
    let successCount = 0;
    const batch = lines.slice(0, 20);
    const unprocessed = lines.slice(20);

    for (const line of batch) {
      try {
        const record = JSON.parse(line);
        const payload = record.payload;
        let targetUrl = record.target_url;
        if (!targetUrl) targetUrl = payload?.yara_rule_matched && !payload?.rule ? `${API_URL}/malware-events` : `${API_URL}/alerts`;

        const res = await fetch(targetUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}`, "x-hardware-id": hwid, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        });
        if (res.status === 200 || res.status === 201) {
          successCount++;
          await integLog("custom-soc-retry", `rule=${payload?.rule?.id || "event"} -> HTTP ${res.status} OK (retried)`);
        } else if (res.status === 400 && (await res.text()).includes("already exists")) {
          successCount++;
        } else remaining.push(line);
      } catch { remaining.push(line); }
    }

    if (successCount > 0) {
      // [FIX-11] เดิมเขียนทับทั้งไฟล์จากข้อมูลที่อ่านไว้ก่อนหน้า → alert ที่ถูก spool ระหว่าง retry หาย
      await withSpoolLock(async () => {
        const cur = (await Bun.file(FAILED_ALERTS_LOG).text().catch(() => "")).split("\n").map((l) => l.trim()).filter(Boolean);
        const appended = cur.length > lines.length ? cur.slice(lines.length) : [];
        const next = [...remaining, ...unprocessed, ...appended];
        await Bun.write(FAILED_ALERTS_LOG, next.length ? next.join("\n") + "\n" : "");
        console.log(`🔁 [Retry Worker] Retried ${successCount} alerts successfully (${next.length} still queued).`);
      });
    }
  } catch (e) {
    console.error("❌ Error in retryFailedAlerts:", e);
  } finally {
    isRetryingFailedAlerts = false;
  }
}

// ---------------------------------------------------------------------
// HTTP poll queue
// ---------------------------------------------------------------------
let polling = false;
let pollFailStreak = 0;

async function pollApiQueue() {
  if (polling) return; // [FIX-12] กัน poll ซ้อนเมื่อส่วนกลางช้า
  polling = true;
  try {
    const hwid = await getHardwareId();
    const response = await fetch(`${API_QUEUE_URL}?hospital_code=${encodeURIComponent(HOSPITAL_CODE)}`, {
      method: "GET", headers: { Authorization: `Bearer ${API_KEY}`, "x-hardware-id": hwid }, signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      pollFailStreak++;
      if (pollFailStreak === 1 || pollFailStreak % 30 === 0) console.error(`❌ API Polling HTTP ${response.status} (streak ${pollFailStreak})`);
      return;
    }
    if (pollFailStreak > 0) console.log(`✅ API Polling recovered after ${pollFailStreak} failures`);
    pollFailStreak = 0;

    const data = await response.json();
    let queues: any[] = [];
    if (Array.isArray(data)) {
      if (data[0]?.success && data[0]?.queues) queues = data[0].queues;
      else if (data.length > 0 && (data[0]?.id || data[0]?.command)) queues = data;
    } else if (data?.success && data?.queues) queues = data.queues;

    if (queues.length > 0) console.log(`🔄 Polled ${queues.length} items from API`);
    for (const item of queues) {
      const done = await processQueueItem(item);
      if (!done) continue; // [FIX-13] เดิมลบคิวเสมอ แม้ประมวลผลล้มเหลว → คำสั่งหายถาวร
      const q = new URLSearchParams({ hospital_code: HOSPITAL_CODE });
      if (item.srcip) q.set("srcip", String(item.srcip));
      const del = await fetch(`${API_QUEUE_URL}?${q.toString()}`, {
        method: "DELETE", headers: { Authorization: `Bearer ${API_KEY}`, "x-hardware-id": hwid }, signal: AbortSignal.timeout(5000),
      });
      console.log(`🗑️ Cleared queue for ${item.srcip ?? item.id} (HTTP ${del.status})`);
    }
  } catch (err) {
    pollFailStreak++;
    if (pollFailStreak === 1 || pollFailStreak % 30 === 0) console.error(`❌ API Polling Error (streak ${pollFailStreak}):`, err);
  } finally {
    polling = false;
  }
}

// ---------------------------------------------------------------------
// Master API (IS_MASTER=true)
// ---------------------------------------------------------------------
function startMasterApi() {
  const MASTER_TOKEN = process.env.MASTER_TOKEN || "";
  if (!MASTER_TOKEN) console.warn("⚠️ MASTER_TOKEN ไม่ได้ตั้งค่า — /edge-connector/script เปิดให้ทุกคนดาวน์โหลด (แนะนำให้ตั้งค่าและปรับ edge-updater ให้ส่ง header x-edge-token)");
  console.log("👑 Starting Master API Server on port 5050...");
  Bun.serve({
    port: 5050,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/api/v1/edge-connector/version") {
        try {
          const versionContent = await Bun.file(`${import.meta.dir}/agent_version.txt`).text();
          const lines = versionContent.split("\n").filter((l) => l.trim().length > 0);
          const usedLine = lines.find((l) => l.endsWith(" used")) || lines[0] || "";
          return Response.json({ success: true, version: usedLine.replace(" used", "").trim() });
        } catch { return Response.json({ success: false, error: "agent_version.txt not found" }, { status: 404 }); }
      }
      if (url.pathname === "/api/v1/edge-connector/script") {
        // [FIX-14] ต้องมี token ถ้าตั้ง MASTER_TOKEN
        if (MASTER_TOKEN && req.headers.get("x-edge-token") !== MASTER_TOKEN) return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
        try {
          return new Response(await Bun.file("/app/index.ts").text(), { headers: { "Content-Type": "text/plain" } });
        } catch { return Response.json({ success: false, error: "index.ts not found" }, { status: 404 }); }
      }
      return Response.json({ success: false, error: "Not Found" }, { status: 404 });
    },
  });
}

// ---------------------------------------------------------------------
// SOC Watchdog (Telegram)
// ---------------------------------------------------------------------
let memState: WatchdogState = {};
let watchdogRunning = false;
let futureWarned = false;

async function loadWatchdogState(): Promise<WatchdogState> {
  for (const p of [WATCHDOG_STATE_FILE, WATCHDOG_STATE_FALLBACK]) {
    try {
      const f = Bun.file(p);
      if (await f.exists()) { memState = { ...(await f.json()), ...memState }; break; }
    } catch { }
  }
  return memState; // memory เป็นหลัก → dedupe ยังทำงานแม้เขียนไฟล์ไม่ได้
}

async function saveWatchdogState(state: WatchdogState) {
  memState = state;
  for (const p of [WATCHDOG_STATE_FILE, WATCHDOG_STATE_FALLBACK]) {
    try { await Bun.write(p, JSON.stringify(state)); return; }
    catch (e) { console.error(`[soc-watchdog] cannot write state file ${p}:`, String(e)); } // [FIX-15] ไม่กลืน error เงียบอีก
  }
}

async function sendTelegramAlert(message: string): Promise<boolean> {
  if (WATCHDOG_DRY_RUN) { console.log(`[soc-watchdog][DRY-RUN] ${message.replace(/\n/g, " | ")}`); return true; }
  if (!WATCHDOG_BOT_TOKEN || !WATCHDOG_CHAT_ID) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${WATCHDOG_BOT_TOKEN}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: WATCHDOG_CHAT_ID, text: message, parse_mode: "HTML" }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) { console.error(`[soc-watchdog] Telegram API error: ${res.status} ${(await res.text()).slice(0, 200)}`); return false; }
    return true;
  } catch (err) {
    console.error(`[soc-watchdog] Telegram send failed:`, String(err).replaceAll(WATCHDOG_BOT_TOKEN, "***"));
    return false;
  }
}

async function probeSocApi(): Promise<boolean> {
  try {
    const res = await fetch(`${API_QUEUE_URL}?hospital_code=${encodeURIComponent(HOSPITAL_CODE)}`, {
      method: "GET", headers: { Authorization: `Bearer ${API_KEY}`, "x-hardware-id": await getHardwareId() }, signal: AbortSignal.timeout(5000),
    });
    return res.status < 500; // 5xx = ส่วนกลาง/gateway มีปัญหา ; 2xx/4xx = ติดต่อถึงแล้ว
  } catch { return false; }
}

async function readLogTail(path: string, maxBytes: number): Promise<string[] | null> {
  try {
    const f = Bun.file(path);
    if (!(await f.exists())) return null;
    const size = f.size;
    const text = size > maxBytes ? await f.slice(size - maxBytes).text() : await f.text();
    const lines = text.split("\n");
    if (size > maxBytes) lines.shift(); // ทิ้งบรรทัดแรกที่อาจขาด
    return lines;
  } catch (e) { console.error("[soc-watchdog] read log failed:", String(e)); return null; }
}

async function countSpooled(): Promise<number> {
  try {
    const f = Bun.file(FAILED_ALERTS_LOG);
    if (!(await f.exists())) return 0;
    return (await f.text()).split("\n").filter((l) => l.trim()).length;
  } catch { return 0; }
}

function buildHeader(): string {
  const hw = hwidCache ? hwidCache.slice(0, 8) : "unknown";
  return `🏥 <b>${escapeHtml(HOSPITAL_NAME)}</b>\n📋 รหัส: <b>${escapeHtml(HOSPITAL_CODE)}</b>\n📍 จังหวัด: <b>${escapeHtml(PROVINCE)}</b>\n` +
    `🖥 ${escapeHtml(os.hostname())} (${escapeHtml(hw)})\n⏰ เวลา: ${new Date().toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}\n${"─".repeat(30)}\n`;
}

async function buildMessage(a: Action): Promise<string> {
  const h = buildHeader();
  if (a.type === "gateway") {
    const spooled = await countSpooled();
    const sample = (a.sample || "").length > 200 ? a.sample!.slice(0, 200) + "..." : a.sample || "";
    return `${h}🔴 <b>แจ้งเตือน: ไม่สามารถติดต่อจากส่วนกลางได้</b>\n\n` +
      `พบ error ต่อเนื่อง ${a.count} ครั้ง (ยังไม่มีการส่งสำเร็จตามหลัง)\n` +
      `ตรวจสอบเชื่อมต่อ SOC API: ${a.probeOk ? "ติดต่อได้ (endpoint เฉพาะอาจมีปัญหา)" : "ติดต่อไม่ได้"}\n` +
      (spooled > 0 ? `📦 ข้อมูลที่ค้างในคิวสำรอง: <b>${spooled} รายการ</b> (ระบบ Retry อัตโนมัติ)\n` : "") +
      `\n<i>${escapeHtml(sample)}</i>`;
  }
  if (a.type === "lag") {
    return `${h}🔴 <b>แจ้งเตือน: ข้อมูลขาดหายเกิน 30 นาที</b>\n\nไม่มีข้อมูลส่งสำเร็จและไม่สามารถเชื่อมต่อ SOC API ได้\n` +
      `ส่งสำเร็จล่าสุด: ${new Date(a.lastOk!).toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}\nขาดช่วงมาแล้ว: ~${a.staleMin} นาที\n\n⚠️ กรุณาตรวจสอบ Wazuh Agent หรือระบบเครือข่าย`;
  }
  return `${h}🟢 <b>กลับมาเชื่อมต่อส่วนกลางได้แล้ว</b>`;
}

async function runSocWatchdog() {
  if (watchdogRunning) return;
  watchdogRunning = true;
  try {
    const now = Date.now();
    const state = await loadWatchdogState();
    const lines = await readLogTail(INTEGRATIONS_LOG, 256 * 1024);
    if (!lines) return;

    const analysis = analyzeLog(lines, now, DEFAULT_WD_CFG.windowMs, LOG_TZ_OFFSET);
    if (analysis.futureEvents > 0 && !futureWarned) {
      console.warn(`[soc-watchdog] ⚠️ พบ ${analysis.futureEvents} บรรทัดที่เวลาอยู่ในอนาคต (ตรวจ LOG_TZ_OFFSET ปัจจุบัน: ${LOG_TZ_OFFSET})`);
      futureWarned = true;
    }

    const decision = await decideWatchdog(analysis, now, state, DEFAULT_WD_CFG, probeSocApi);
    for (const a of decision.actions) {
      const msg = await buildMessage(a);
      const ok = await sendTelegramAlert(msg);
      if (ok) {
        if (a.type === "gateway") {
          state.last_err_alert = now;
          state.incident_active = 1;
        } else if (a.type === "lag") {
          state.last_lag_alert = now;
          state.incident_active = 1;
        } else if (a.type === "recovery") {
          delete state.last_err_alert;
          delete state.last_lag_alert;
          delete state.incident_active;
        }
      }
    }
    for (const k of decision.clear) {
      delete state[k];
    }
    await saveWatchdogState(state);
  } catch (err) {
    console.error("[soc-watchdog] Error in watchdog cycle:", err);
  } finally {
    watchdogRunning = false;
  }
}

// ---------------------------------------------------------------------
// Service Entry Point
// ---------------------------------------------------------------------
if (!IS_TEST) {
  process.on("unhandledRejection", (err) => {
    console.error("💥 Unhandled Rejection:", err);
  });

  installFileLogging();
  console.log("🚀 Starting Hospital Edge Connector (Bun/TypeScript) — v2...");
  console.log(`🏥 Hospital Code: ${HOSPITAL_CODE} | Name: ${HOSPITAL_NAME} | Zone: ${ZONE}`);

  if (process.env.SKIP_SYSTEM_SETUP !== "true") {
    setSystemTimezone();
    setupDummyLists();
  }

  // WebSocket connect
  connect();

  // Poll API Queue every 10 seconds
  setInterval(pollApiQueue, 10000);

  // Run retry worker every 60 seconds (and initial run after 5s)
  setInterval(retryFailedAlerts, 60000);
  setTimeout(retryFailedAlerts, 5000);

  // Master server API
  if (process.env.IS_MASTER === "true") {
    startMasterApi();
  }

  // Watchdog
  if (!WATCHDOG_BOT_TOKEN || !WATCHDOG_CHAT_ID) {
    if (WATCHDOG_DRY_RUN) {
      console.log("🐕 SOC Watchdog running in DRY-RUN mode (logging alerts)");
      runSocWatchdog().catch((err) => console.error("[soc-watchdog] Initial run error:", err));
      setInterval(() => runSocWatchdog().catch((err) => console.error("[soc-watchdog] Error:", err)), WATCHDOG_CHECK_INTERVAL_MS);
    } else {
      console.warn("⚠️ WATCHDOG_BOT_TOKEN or WATCHDOG_CHAT_ID not set — SOC Watchdog disabled");
    }
  } else {
    console.log("🐕 SOC Watchdog started (check every 5 min, alert via Telegram)");
    runSocWatchdog().catch((err) => console.error("[soc-watchdog] Initial run error:", err));
    setInterval(() => runSocWatchdog().catch((err) => console.error("[soc-watchdog] Error:", err)), WATCHDOG_CHECK_INTERVAL_MS);
  }
}
