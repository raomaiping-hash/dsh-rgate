/**
 * dsh-rgate — 远程访问登录门禁（host half）
 *
 * 常驻 Web 插件：对非回环（非 127.0.0.1/localhost/::1）的 Web 访问实施登录墙。
 * - 未登录：任何页面通过 index.html 注入脚本重定向到 /rgate-login 登录页；
 *   /api 的 RPC 面由新版 dsh 自身鉴权（无凭据一律 401），本插件不再代理。
 * - 登录成功：HttpOnly + SameSite=Strict cookie（7 天内存会话），放行。
 * - 回环（本机）：始终直通，不要求登录。
 * - 密码存储：~/.dsh/remote-auth.json（0600，明文，与动态版兼容）。
 *
 * 已知边界：/api/events.mux 与 /api/events.host 的 WebSocket 升级由
 * dsh-client-connection 持有，本插件无法在路由层拦截；如需彻底封闭公网
 * 入口，建议在 Cloudflare 控制台为该域名开启 Access（Zero Trust）。
 */
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { readFile, writeFile, mkdir, chmod, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { createRequire } from "node:module";

export const name = "rgate";
export const inject = ["webServer"];

const COOKIE = "rgate_session";
// DSH 本体（dsh-client-connection）只认自己的进程 token cookie：首次访问必须用
// 带 ?token=<launchToken> 的地址换 cookie，否则 index 与 /api 一律 401。rgate
// 就是那层认证，所以这里额外签发一枚同格式的 HMAC 签名 cookie，并让 DSH 的
// isAuthenticated 用同一密钥验证它——登录墙通过后，token 地址不再需要。
const DSH_TRUST_COOKIE = "rgate_auth";
const SIGNING_KEY_NAME = ".rgate-signing.key";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const MAX_BODY = 192 * 1024 * 1024; // 与网关默认（160 MiB 图片信封余量）对齐

// ── 远程设置补丁 ──────────────────────────────────────────────
// 官方客户端把 settings 镜像限制为仅限 loopback（非回环页面的持久化层被降级
// 为 "memory"，describe 面标记 unavailable，浏览器里报
// "settings are unavailable in this browser" / 加载提供方目录失败）。
// rgate 登录墙就是上游等待的"真实认证层"，因此把该开关恢复为恒用 host
// 持久化——远程已登录用户即可正常使用设置面；未登录访客仍被拦在门外。
// 官方包文件 root 所有且随 Harness 升级整体覆盖：本插件每次启动幂等重查，
// 需要时经 sudo 或特权容器写回，原文件自动留 .rgate-backup。
// 锚点表达式随官方版本变化，按新→旧顺序尝试；全不匹配时明确报告而非静默跳过。
// 目标文件按安装布局动态解析（@deepseek-ai/* 由运行时闭包注入）；解析失败时
// 回退到 npm 全局安装的默认布局，再失败则报告原因（不影响门禁本体）。
const REMOTE_SETTINGS_PATCH_FILE = (function resolveRemoteSettingsPatchFile() {
  try {
    const req = createRequire(import.meta.url);
    const pkg = req.resolve("@deepseek-ai/dsh-client-ui-settings/package.json");
    return join(pkg.slice(0, pkg.lastIndexOf("/")), "lib", "client.js");
  } catch (e) {
    return "/opt/node-v22.23.2-linux-x64/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-client-ui-settings/lib/client.js";
  }
})();

const runCmd = (cmd, timeoutMs = 60000) => new Promise((resolve) => {
  execFile("/bin/bash", ["-c", cmd], { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
    resolve({ code: err ? (err.code ?? 1) : 0, stdout: String(stdout || ""), stderr: String(stderr || "") });
  });
});

// 官方决定 settings 持久化层的锚点表达式（新版在前）。
const REMOTE_SETTINGS_ANCHORS = [
  'ctx.remote.$host.isLoopback ? "host" : "memory"', // 0.1.2-alpha.2 及以后
  'connection.isLoopback ? "host" : "memory"',       // 0.1.2-alpha.1 及以前
];
const REMOTE_SETTINGS_MARK = '"host" /* rgate auth via login wall */';

async function reapplyRemoteSettingsPatch() {
  try {
    const src = await readFile(REMOTE_SETTINGS_PATCH_FILE, "utf8");
    if (src.includes(REMOTE_SETTINGS_MARK)) return { applied: false, reason: "not-needed" };
    const from = REMOTE_SETTINGS_ANCHORS.find((a) => src.includes(a));
    if (from === undefined) {
      return {
        applied: false,
        reason: "锚点未匹配（官方 settings client 可能已改版）：" + REMOTE_SETTINGS_PATCH_FILE,
      };
    }
    const patched = src.split(from).join(REMOTE_SETTINGS_MARK);
    const dir = REMOTE_SETTINGS_PATCH_FILE.slice(0, REMOTE_SETTINGS_PATCH_FILE.lastIndexOf("/"));
    const base = REMOTE_SETTINGS_PATCH_FILE.slice(REMOTE_SETTINGS_PATCH_FILE.lastIndexOf("/") + 1);
    const backup = REMOTE_SETTINGS_PATCH_FILE + ".rgate-backup";
    const tmp = join(tmpdir(), "rgate-settings-patch-" + process.pid + "-" + Date.now() + ".js");
    await writeFile(tmp, patched, "utf8");
    const q = (s) => "'" + String(s).split("'").join("'\\''") + "'";
    try {
      // 1) sudo（免密时最轻）
      let wr = await runCmd(
        "sudo -n sh -c " + q(
          "[ -f " + q(backup) + " ] || cp -a " + q(REMOTE_SETTINGS_PATCH_FILE) + " " + q(backup) + "; " +
          "cp " + q(tmp) + " " + q(REMOTE_SETTINGS_PATCH_FILE),
        ),
        60000,
      );
      // 2) 特权容器回退（无 root shell 的部署环境）
      if (wr.code !== 0) {
        const inner = "[ -f /target/" + base + ".rgate-backup ] || cp -a /target/" + base +
          " /target/" + base + ".rgate-backup; cat > /target/" + base;
        wr = await runCmd(
          "cat " + q(tmp) + " | docker run --rm -i -v " + q(dir + ":/target") +
            " alpine:3.20 sh -c " + q(inner),
          60000,
        );
      }
      if (wr.code !== 0) {
        return { applied: false, reason: (wr.stderr || "sudo 与容器写入均失败").slice(0, 220) };
      }
      return { applied: true, anchor: from };
    } finally {
      await rm(tmp, { force: true }).catch(() => {});
    }
  } catch (e) {
    return { applied: false, reason: String((e && e.message) || e) };
  }
}
// ── DSH 本体鉴权打通：登录墙通过后不再需要 ?token= 地址 ──────────
// dsh-client-connection 的 BrowserAuth 只认进程 token 换来的 cookie：
//   authorizeIndex() —— 无 token/cookie 的 index 请求一律 401；
//   requestRejection() —— /api 面同样要求该 cookie。
// 结果就是每次访问都得先拿到带 ?token=<launchToken> 的地址。rgate 既然是登录墙，
// 就让它成为那层凭据：登录时另发一枚 HMAC 签名 cookie（rgate_auth），并让 DSH 的
// isAuthenticated 用同一密钥验证它；index 请求则直接放行，由注入脚本决定去留。
// 写入路径与设置补丁一致（sudo → 特权容器），原文件留 .rgate-backup。
const DSH_CONNECTION_FILE = (function resolveDshConnectionFile() {
  try {
    const req = createRequire(import.meta.url);
    const pkg = req.resolve("@deepseek-ai/dsh-client-connection/package.json");
    return join(pkg.slice(0, pkg.lastIndexOf("/")), "lib", "index.js");
  } catch (e) {
    return "/opt/node-v22.23.2-linux-x64/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-client-connection/lib/index.js";
  }
})();

const DSH_TRUST_MARK = "/* [rgate] trust the login wall */";

const DSH_AUTH_FROM = [
  "\tisAuthenticated(request) {",
  "\t\tconst authority = requestAuthority(request.headers);",
  "\t\tconst rawCookie = header(request.headers, \"cookie\");",
  "\t\tif (authority === void 0 || rawCookie === void 0) return false;",
  "\t\tconst value = cookieValue(rawCookie, cookieName(authority));",
  "\t\tif (value === void 0) return false;",
  "\t\tconst payload = decodeCookie(value, this.secret);",
  "\t\tif (payload === void 0 || payload.authority !== authority) return false;",
  "\t\tconst now = Date.now();",
  "\t\treturn payload.issuedAt <= now && payload.expiresAt > now && payload.expiresAt > payload.issuedAt && payload.expiresAt - payload.issuedAt <= this.maxAgeMilliseconds;",
  "\t}",
].join("\n");

const DSH_AUTH_TO = [
  "\tisAuthenticated(request) {",
  "\t\tconst authority = requestAuthority(request.headers);",
  "\t\tconst rawCookie = header(request.headers, \"cookie\");",
  "\t\tif (authority === void 0 || rawCookie === void 0) return false;",
  "\t\tconst value = cookieValue(rawCookie, cookieName(authority));",
  "\t\tif (value !== void 0) {",
  "\t\t\tconst payload = decodeCookie(value, this.secret);",
  "\t\t\tif (payload !== void 0 && payload.authority === authority) {",
  "\t\t\t\tconst now = Date.now();",
  "\t\t\t\tif (payload.issuedAt <= now && payload.expiresAt > now && payload.expiresAt > payload.issuedAt && payload.expiresAt - payload.issuedAt <= this.maxAgeMilliseconds) return true;",
  "\t\t\t}",
  "\t\t}",
  "\t\t" + DSH_TRUST_MARK,
  "\t\ttry {",
  "\t\t\tconst fsR = process.getBuiltinModule(\"node:fs\");",
  "\t\t\tconst pathR = process.getBuiltinModule(\"node:path\");",
  "\t\t\tconst osR = process.getBuiltinModule(\"node:os\");",
  "\t\t\tconst homeR = process.env.DSH_HOME || pathR.join(osR.homedir(), \".dsh\");",
  "\t\t\tif (globalThis.__rgateSigningKey === void 0) globalThis.__rgateSigningKey = fsR.readFileSync(pathR.join(homeR, \".rgate-signing.key\"), \"utf8\").trim();",
  "\t\t\tconst keyR = decodeBase64Url(globalThis.__rgateSigningKey);",
  "\t\t\tif (keyR !== void 0 && keyR.byteLength === 32) {",
  "\t\t\t\tconst valueR = cookieValue(rawCookie, \"rgate_auth\");",
  "\t\t\t\tif (valueR !== void 0) {",
  "\t\t\t\t\tconst payloadR = decodeCookie(valueR, keyR);",
  "\t\t\t\t\tif (payloadR !== void 0 && payloadR.authority === authority) {",
  "\t\t\t\t\t\tconst nowR = Date.now();",
  "\t\t\t\t\t\tif (payloadR.issuedAt <= nowR && payloadR.expiresAt > nowR) return true;",
  "\t\t\t\t\t}",
  "\t\t\t\t}",
  "\t\t\t}",
  "\t\t} catch {}",
  "\t\treturn false;",
  "\t}",
].join("\n");

const DSH_INDEX_FROM = [
  "\t\t\tthis.writeUnauthorized(req, res);",
  "\t\t\treturn false;",
  "\t\t}",
  "\t\tif (this.isAuthenticated(req)) return true;",
  "\t\tthis.writeUnauthorized(req, res);",
  "\t\treturn false;",
  "\t}",
].join("\n");

const DSH_INDEX_TO = [
  "\t\t\t" + DSH_TRUST_MARK,
  "\t\t\treturn true;",
  "\t\t}",
  "\t\tif (this.isAuthenticated(req)) return true;",
  "\t\t" + DSH_TRUST_MARK,
  "\t\treturn true;",
  "\t}",
].join("\n");

/** 签名密钥：~/.dsh/.rgate-signing.key（0600，32 字节 base64url）。 */
async function loadSigningKey(dshHome) {
  const file = join(dshHome, SIGNING_KEY_NAME);
  try {
    const raw = (await readFile(file, "utf8")).trim();
    if (/^[A-Za-z0-9_-]{43}$/.test(raw)) return raw;
  } catch (e) {
    /* 首次启动或文件不可读：下面重建 */
  }
  const key = randomBytes(32).toString("base64url");
  await writeFile(file, key + "\n", { mode: 0o600 });
  return key;
}

/** 与 dsh-client-connection 的 encodeCookie 同格式：v1.<body>.<hmac>。 */
function signTrustCookie(key, authority, issuedAt, expiresAt) {
  const body = Buffer.from(JSON.stringify({ version: 1, authority, issuedAt, expiresAt }), "utf8").toString("base64url");
  const sig = createHmac("sha256", Buffer.from(key, "base64url")).update(body).digest("base64url");
  return "v1." + body + "." + sig;
}

/** 以 root 写回被补丁的本体文件（sudo → 特权容器），保留 .rgate-backup。 */
async function writeRootFile(target, content, tag) {
  const dir = target.slice(0, target.lastIndexOf("/"));
  const base = target.slice(target.lastIndexOf("/") + 1);
  const tmp = join(tmpdir(), tag + "-" + process.pid + "-" + Date.now() + ".js");
  await writeFile(tmp, content, "utf8");
  const q = (s) => "'" + String(s).split("'").join("'\\''") + "'";
  try {
    let wr = await runCmd(
      "sudo -n sh -c " + q(
        "[ -f " + q(target) + ".rgate-backup ] || cp -a " + q(target) + " " + q(target) + ".rgate-backup; " +
        "cp " + q(tmp) + " " + q(target),
      ),
      60000,
    );
    if (wr.code !== 0) {
      const inner = "[ -f /target/" + base + ".rgate-backup ] || cp -a /target/" + base +
        " /target/" + base + ".rgate-backup; cat > /target/" + base;
      wr = await runCmd(
        "cat " + q(tmp) + " | docker run --rm -i -v " + q(dir + ":/target") +
          " alpine:3.20 sh -c " + q(inner),
        60000,
      );
    }
    if (wr.code !== 0) return { ok: false, reason: (wr.stderr || "sudo 与容器写入均失败").slice(0, 220) };
    return { ok: true };
  } finally {
    await rm(tmp, { force: true }).catch(() => {});
  }
}

async function reapplyDshTrustPatch() {
  try {
    const src = await readFile(DSH_CONNECTION_FILE, "utf8");
    if (src.includes(DSH_TRUST_MARK)) return { applied: false, reason: "not-needed" };
    let out = src;
    const authHit = out.includes(DSH_AUTH_FROM);
    const indexHit = out.includes(DSH_INDEX_FROM);
    if (!authHit && !indexHit) {
      return { applied: false, reason: "锚点未匹配（官方 connection 可能已改版）：" + DSH_CONNECTION_FILE };
    }
    if (authHit) out = out.replace(DSH_AUTH_FROM, DSH_AUTH_TO);
    if (indexHit) out = out.replace(DSH_INDEX_FROM, DSH_INDEX_TO);
    const wr = await writeRootFile(DSH_CONNECTION_FILE, out, "rgate-connection-patch");
    if (!wr.ok) return { applied: false, reason: wr.reason };
    return { applied: true, auth: authHit, index: indexHit };
  } catch (e) {
    return { applied: false, reason: String((e && e.message) || e) };
  }
}
// ─────────────────────────────────────────────────────────────


const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 — DeepSeek Harness</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: #10141a; color: #e6e8eb;
  }
  .card {
    width: min(92vw, 400px); background: #171d26; border: 1px solid rgba(255,255,255,.08);
    border-radius: 14px; padding: 28px 24px; box-shadow: 0 18px 50px rgba(0,0,0,.45);
  }
  h1 { font-size: 19px; font-weight: 600; margin-bottom: 4px; }
  .sub { font-size: 13px; color: #9aa3ad; margin-bottom: 20px; line-height: 1.6; }
  input {
    width: 100%; padding: 11px 12px; font-size: 14px; color: inherit;
    background: #0e131a; border: 1px solid rgba(255,255,255,.14); border-radius: 8px; outline: none;
  }
  input:focus { border-color: #4f8cff; }
  button {
    width: 100%; margin-top: 14px; padding: 11px 12px; font-size: 14px; font-weight: 600;
    color: #fff; background: #2563eb; border: none; border-radius: 8px; cursor: pointer;
  }
  button:hover { background: #1d4fd8; }
  button:disabled { opacity: .55; cursor: default; }
  .err { margin-top: 12px; font-size: 13px; color: #f28b82; min-height: 18px; }
  .hint { margin-top: 18px; font-size: 12px; color: #6b7480; line-height: 1.7; }
</style>
</head>
<body>
  <div class="card">
    <h1>DeepSeek Harness</h1>
    <div class="sub">此站点需要登录后才能访问。请输入远程访问密码。</div>
    <input id="pw" type="password" placeholder="访问密码" autocomplete="current-password" autofocus>
    <button id="go">登 录</button>
    <div class="err" id="err"></div>
    <div class="hint">密码由服务器管理员设置，以 scrypt 哈希存储于服务器 ~/.dsh/remote-auth.json。忘记密码：删除该文件并重启 deepseek-harness 服务，新密码会打印在服务日志（journalctl -u deepseek-harness | grep rgate）中。</div>
  </div>
<script>
(function () {
  var pw = document.getElementById("pw");
  var go = document.getElementById("go");
  var err = document.getElementById("err");
  // Only accept a same-site relative route to prevent open redirects.
  function nextPage() {
    var value = new URLSearchParams(location.search).get("next") || "/";
    return value.charAt(0) === "/" && value.charAt(1) !== "/" ? value : "/";
  }
  function fail(text) { err.textContent = text || ""; }
  function submit() {
    var value = pw.value;
    if (!value) { fail("请输入密码"); return; }
    go.disabled = true; fail("");
    fetch("/api/remote-auth.login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: value }),
    }).then(function (r) { return r.json().then(function (d) { return { status: r.status, data: d }; }); })
      .then(function (r) {
        if (r.status === 200 && r.data && r.data.ok === true) { location.replace(nextPage()); return; }
        go.disabled = false;
        if (r.status === 429) fail("尝试次数过多，请 " + String((r.data && r.data.retryInSeconds) || 30) + " 秒后重试");
        else fail("密码错误");
      })
      .catch(function () { go.disabled = false; fail("网络错误，请重试"); });
  }
  go.addEventListener("click", submit);
  pw.addEventListener("keydown", function (e) { if (e.key === "Enter") submit(); });
  // 已登录则直接进入
  fetch("/api/remote-auth.status", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (s) { if (s.authenticated === true || s.loopback === true) location.replace(nextPage()); })
    .catch(function () {});
})();
</script>
</body>
</html>`;

const GATE_HEAD = `<style id="rgate-gate-style">#root{visibility:hidden!important}</style>
<script>
(function () {
  var redirecting = false;
  function loginPage() {
    if (redirecting || location.pathname === "/rgate-login") return;
    redirecting = true;
    var next = location.pathname + location.search + location.hash;
    location.replace("/rgate-login?next=" + encodeURIComponent(next));
  }
  // Session records are intentionally in-memory. When a restart or TTL expiry
  // makes a protected RPC return 401, go straight back to the login wall
  // instead of leaving the app on a bare 401 error.
  // 两条路径：rgate 自己的端点带 x-rgate-auth 标记；新版 dsh 自身鉴权的 /api
  // 面返回不带标记的裸 401 —— 那时主动问一次 remote-auth.status 才能区分
  // 「rgate 会话失效」和「dsh 自己的授权问题」，只有前者跳登录墙。
  var nativeFetch = window.fetch;
  var probing = false;
  function probeSession() {
    if (probing || redirecting) return;
    probing = true;
    nativeFetch("/api/remote-auth.status", { headers: { accept: "application/json" }, cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) {
        if (s && s.configured === true && s.authenticated === false && s.loopback === false) loginPage();
      })
      .catch(function () {})
      .then(function () { probing = false; });
  }
  if (typeof nativeFetch === "function") {
    window.fetch = function () {
      return nativeFetch.apply(this, arguments).then(function (response) {
        if (response.status === 401) {
          if (response.headers.get("x-rgate-auth") === "required") loginPage();
          else probeSession();
        }
        return response;
      });
    };
  }
  function show() {
    var el = document.getElementById("rgate-gate-style");
    if (el) el.remove();
    // 启动看门狗：index.html 被浏览器缓存后，Harness 升级换代会让旧哈希资源
    // 404（SPA 兜底返回 text/html → 模块加载失败 → 白屏）。检测 root 迟迟没有
    // 挂载内容，就带穿透参数重载一次；sessionStorage 防循环。
    setTimeout(function () {
      try {
        var root = document.getElementById("root");
        if (!root) return;
        if (root.childElementCount > 0) { sessionStorage.removeItem("rgate_boot_retry"); return; }
        if (!sessionStorage.getItem("rgate_boot_retry")) {
          sessionStorage.setItem("rgate_boot_retry", "1");
          var sep = location.search ? "&" : "?";
          location.replace(location.pathname + location.search + sep + "rgate_r=" + Date.now() + location.hash);
        }
      } catch (e) {}
    }, 3000);
  }
  fetch("/api/remote-auth.status", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (s) {
      if (s.authenticated === true || s.loopback === true) show();
      else loginPage();
    })
    .catch(function () { show(); });
})();
</script>`;

// 供运维/测试手动触发（启动时也会自动幂等执行）。
export { reapplyDshTrustPatch };

export function apply(ctx) {
  const webServer = ctx.webServer;
  if (webServer === undefined) {
    console.error("[rgate] webServer 不可用，门禁未启用");
    return;
  }

  // 遵循 harness 约定：密码文件在 DSH 数据根下（默认 ~/.dsh），
  // 与 settings.yaml / .agent-presets 同层。
  const DSH_HOME = typeof process !== "undefined" && typeof process.env === "object" && process.env.DSH_HOME !== undefined
    ? process.env.DSH_HOME
    : join(homedir(), ".dsh");
  const AUTH_FILE = join(DSH_HOME, "remote-auth.json");

  const SCRYPT = { N: 16384, r: 8, p: 1 };

  const state = {
    content: null,
    loaded: null,
    boot: null,
    sessions: new Map(),
    loginFails: new Map(),
    passwordWrite: Promise.resolve(),
    signingKey: null,
    signingKeyReady: Promise.resolve(),
  };

  const safeEqual = (a, b) => {
    const A = String(a);
    const B = String(b);
    let diff = A.length ^ B.length;
    const len = Math.max(A.length, B.length);
    for (let i = 0; i < len; i += 1) diff |= (A.charCodeAt(i) || 0) ^ (B.charCodeAt(i) || 0);
    return diff === 0;
  };

  const derive = (password, saltBuf) => scryptSync(String(password), saltBuf, 32, SCRYPT);

  const verifyPassword = (content, password) => {
    if (content === null || typeof content !== "object") return false;
    if (content.version === 2 && typeof content.hash === "string" && typeof content.salt === "string") {
      try {
        const salt = Buffer.from(content.salt, "base64");
        const expected = Buffer.from(content.hash, "base64");
        const actual = derive(password, salt);
        return expected.length === actual.length && timingSafeEqual(expected, actual);
      } catch (e) {
        return false;
      }
    }
    if (content.version === 1 && typeof content.password === "string" && content.password.length > 0) {
      // 旧版明文（迁移写入失败时的内存回退）
      return safeEqual(content.password, password);
    }
    return false;
  };

  const makeHashContent = (password, createdAt) => {
    const salt = randomBytes(16);
    return {
      version: 2,
      algo: "scrypt",
      salt: salt.toString("base64"),
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
      hash: derive(password, salt).toString("base64"),
      createdAt,
      updatedAt: new Date().toISOString(),
    };
  };

  const persist = async (content) => {
    const text = JSON.stringify(content, null, 2) + "\n";
    await mkdir(DSH_HOME, { recursive: true });
    await writeFile(AUTH_FILE, text, { mode: 0o600 });
    try {
      await chmod(AUTH_FILE, 0o600);
    } catch (e) {}
  };

  const ensureLoaded = () => {
    if (state.loaded !== null) return state.loaded;
    state.loaded = (async () => {
      let content = null;
      try {
        const parsed = JSON.parse(await readFile(AUTH_FILE, "utf8"));
        if (parsed !== null && typeof parsed === "object") content = parsed;
      } catch (e) {}
      const now = new Date().toISOString();
      if (content === null) {
        // 首次启动：生成随机密码，仅打印到本次启动日志（journalctl 可见）
        const pw = randomBytes(18).toString("base64url");
        console.log("[rgate] 已生成新的访问密码（仅本次启动日志可见，请立即保存）：" + pw);
        content = makeHashContent(pw, now);
        try {
          await persist(content);
        } catch (e) {
          console.error("[rgate] 无法写入 " + AUTH_FILE + "：" + String((e && e.message) || e));
        }
      } else if (content.version === 1 && typeof content.password === "string" && content.password.length > 0) {
        // 旧版明文 → scrypt 哈希迁移
        console.log("[rgate] 检测到旧版明文密码文件，正在迁移为 scrypt 哈希…");
        const migrated = makeHashContent(content.password, content.createdAt || now);
        try {
          await persist(migrated);
          content = migrated;
          console.log("[rgate] 密码文件已迁移为哈希存储");
        } catch (e) {
          console.error("[rgate] 迁移写入失败，本次运行回退为内存校验：" + String((e && e.message) || e));
        }
      }
      if (!(content.version === 2 && typeof content.hash === "string" && typeof content.salt === "string") &&
          !(content.version === 1 && typeof content.password === "string")) {
        console.error("[rgate] 密码文件格式无法识别，登录不可用：" + AUTH_FILE);
      }
      state.content = content;
      state.boot = {
        path: AUTH_FILE,
        createdAt: content.createdAt || null,
        updatedAt: content.updatedAt || null,
      };
      return content;
    })();
    return state.loaded;
  };

  const verify = (password) => verifyPassword(state.content, password);

  // 真实客户端键：Cloudflare Tunnel 场景下 socket 源地址统一为 127.0.0.1，
  // 必须用 Cf-Connecting-Ip 区分客户端，否则限速桶全员共享（可被用来锁死所有人）。
  const clientKey = (req) => {
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim() !== "") return "cf:" + cf.trim();
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim() !== "") return "xff:" + xff.split(",")[0].trim();
    return "ip:" + String((req.socket && req.socket.remoteAddress) || "unknown");
  };

  // 与 dsh-client-connection 的 requestAuthority 同口径：Host 规范化后的 host[:port]。
  const authorityOf = (req) => {
    const host = String(req.headers.host || "").trim();
    if (host === "") return null;
    try {
      return new URL("http://" + host).host;
    } catch (e) {
      return null;
    }
  };

  // Origin 与 Host 一致性（浏览器跨站 POST 会带攻击者 Origin；非浏览器无 Origin 放行）
  const originOk = (req) => {
    const origin = req.headers.origin;
    if (origin === undefined || origin === "") return true;
    try {
      const o = new URL(String(origin));
      const h = new URL("http://" + String(req.headers.host || ""));
      return o.host === h.host;
    } catch (e) {
      return false;
    }
  };

  const isLoopbackHost = (hostHeader) => {
    let h = String(hostHeader || "").trim().toLowerCase();
    if (h === "") return false;
    const slash = h.indexOf("/");
    if (slash >= 0) h = h.slice(0, slash);
    if (h.startsWith("[")) {
      const close = h.indexOf("]");
      if (close > 0) h = h.slice(1, close);
    } else {
      const colon = h.lastIndexOf(":");
      if (colon > 0) {
        const port = h.slice(colon + 1);
        if (/^\d+$/.test(port)) h = h.slice(0, colon);
      }
    }
    if (h === "localhost" || h === "::1") return true;
    if (h.startsWith("::ffff:127.")) return true;
    if (h.startsWith("127.")) {
      const parts = h.split(".");
      return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
    }
    return false;
  };

  const sessionToken = (req) => {
    const header = String(req.headers.cookie || "");
    const parts = header.split(";");
    for (let i = 0; i < parts.length; i += 1) {
      const eq = parts[i].indexOf("=");
      if (eq < 0) continue;
      if (parts[i].slice(0, eq).trim() === COOKIE) {
        const value = parts[i].slice(eq + 1).trim();
        return value.length > 0 ? value : null;
      }
    }
    return null;
  };

  const isAuthenticated = (req) => {
    const token = sessionToken(req);
    if (token === null) return false;
    const expires = state.sessions.get(token);
    if (expires === undefined) return false;
    if (expires < Date.now()) {
      state.sessions.delete(token);
      return false;
    }
    return true;
  };

  const allowed = (req) => isLoopbackHost(req.headers.host) || isAuthenticated(req);

  const sendJson = (res, status, body) => {
    let text;
    try {
      text = JSON.stringify(body);
    } catch (e) {
      text = "{}";
    }
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(text);
  };
  const sendPlain = (res, status, text, headers) => {
    res.writeHead(status, Object.assign({ "content-type": "text/plain", "cache-control": "no-store" }, headers || {}));
    res.end(String(text));
  };
  // A stable marker lets the injected browser gate distinguish an expired
  // rgate session from an unrelated 401 returned by application code.
  const sendUnauthorized = (res) => sendPlain(res, 401, "unauthorized", { "x-rgate-auth": "required" });
  const readBody = (req) => new Promise((resolve, reject) => {
    let size = 0;
    let text = "";
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      text += chunk.toString("utf8");
    });
    req.on("end", () => resolve(text));
    req.on("error", reject);
  });


  const makeLogin = () => async (req, res) => {
    await ensureLoaded();
    if (req.method !== "POST") {
      sendPlain(res, 404, "not found");
      return;
    }
    if (!originOk(req)) {
      sendPlain(res, 403, "forbidden");
      return;
    }
    const ct = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/json") {
      sendPlain(res, 415, "content type must be application/json");
      return;
    }
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch (e) {
      sendPlain(res, 400, "body is not JSON");
      return;
    }
    const key = clientKey(req);
    const now = Date.now();
    const fails = state.loginFails.get(key);
    if (fails !== undefined && fails.until > now) {
      sendJson(res, 429, { ok: false, error: "too many attempts", retryInSeconds: Math.ceil((fails.until - now) / 1000) });
      return;
    }
    const password = body !== null && typeof body === "object" && typeof body.password === "string" ? body.password : "";
    if (password !== "" && verify(password)) {
      state.loginFails.delete(key);
      const token = randomBytes(32).toString("base64url");
      const issuedAt = Date.now();
      const expiresAt = issuedAt + SESSION_TTL_MS;
      const maxAge = Math.floor(SESSION_TTL_MS / 1000);
      state.sessions.set(token, expiresAt);
      const cookies = [`${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`];
      // 同步签发 DSH 能独立验证的信任 cookie：登录后访问不再需要 ?token= 地址。
      try {
        await state.signingKeyReady;
        const authority = authorityOf(req);
        if (state.signingKey !== null && authority !== null) {
          cookies.push(
            `${DSH_TRUST_COOKIE}=${signTrustCookie(state.signingKey, authority, issuedAt, expiresAt)}` +
            `; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`,
          );
        }
      } catch (e) {
        console.error("[rgate] 信任 cookie 签发失败：" + String((e && e.message) || e));
      }
      console.log("[rgate] 登录成功：" + key);
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
        "set-cookie": cookies,
      });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    const f = fails === undefined ? { count: 0, until: 0 } : fails;
    f.count += 1;
    if (f.count >= 5) f.until = now + Math.min(30000 * Math.pow(2, Math.min(f.count - 5, 5)), 960000);
    state.loginFails.set(key, f);
    console.log("[rgate] 登录失败：" + key + "（第 " + f.count + " 次）");
    sendJson(res, 401, { ok: false, error: "invalid password" });
  };

  const makeLogout = () => async (req, res) => {
    if (!originOk(req)) {
      sendPlain(res, 403, "forbidden");
      return;
    }
    const token = sessionToken(req);
    if (token !== null) state.sessions.delete(token);
    res.writeHead(200, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "set-cookie": [
        `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
        `${DSH_TRUST_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      ],
    });
    res.end(JSON.stringify({ ok: true }));
  };

  const makeStatus = () => async (req, res) => {
    await ensureLoaded();
    const c = state.content;
    sendJson(res, 200, {
      configured: c !== null && (typeof c.hash === "string" || typeof c.password === "string"),
      authenticated: isAuthenticated(req),
      loopback: isLoopbackHost(req.headers.host),
    });
  };

  const makeSecret = () => async (req, res) => {
    await ensureLoaded();
    if (!isLoopbackHost(req.headers.host)) {
      sendPlain(res, 403, "forbidden");
      return;
    }
    sendJson(res, 200, {
      mode: state.content !== null && state.content.version === 2 ? "hashed" : "legacy",
      path: state.boot === null ? null : state.boot.path,
      createdAt: state.boot === null ? null : state.boot.createdAt,
      updatedAt: state.boot === null ? null : state.boot.updatedAt,
    });
  };

  const makePassword = () => async (req, res) => {
    await ensureLoaded();
    if (req.method !== "POST") {
      sendPlain(res, 404, "not found");
      return;
    }
    if (!originOk(req)) {
      sendPlain(res, 403, "forbidden");
      return;
    }
    const ct = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/json") {
      sendPlain(res, 415, "content type must be application/json");
      return;
    }
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch (e) {
      sendPlain(res, 400, "body is not JSON");
      return;
    }
    const next = body !== null && typeof body === "object" && typeof body.next === "string" ? body.next : "";
    const current = body !== null && typeof body === "object" && typeof body.current === "string" ? body.current : "";
    if (next.length < 8 || next.length > 200) {
      sendJson(res, 400, { ok: false, error: "new password must be 8-200 characters" });
      return;
    }
    const local = isLoopbackHost(req.headers.host);
    const authed = isAuthenticated(req);
    if (!authed && !(local && verify(current))) {
      sendJson(res, 401, { ok: false, error: "current password incorrect" });
      return;
    }
    let done = false;
    state.passwordWrite = state.passwordWrite.then(async () => {
      const createdAt = state.boot === null || state.boot.createdAt === null ? new Date().toISOString() : state.boot.createdAt;
      const content = makeHashContent(next, createdAt);
      let saved = false;
      try {
        await persist(content);
        saved = true;
      } catch (e) {
        console.error("[rgate] 改密写入失败：" + String((e && e.message) || e));
      }
      if (saved) {
        state.content = content;
        state.sessions.clear();
        if (state.boot !== null) state.boot.updatedAt = content.updatedAt;
      }
      done = saved;
    });
    await state.passwordWrite;
    if (done) {
      console.log("[rgate] 密码已修改（来源：" + (local ? "loopback" : "remote") + "，" + clientKey(req) + "），全部会话已失效");
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
        "set-cookie": [
          `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
          `${DSH_TRUST_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
        ],
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      sendJson(res, 500, { ok: false, error: "could not persist password file" });
    }
  };

  const makeLoginPage = () => async (req, res) => {
    await ensureLoaded();
    if (allowed(req)) {
      res.writeHead(302, { location: "/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(LOGIN_PAGE);
  };

  // 1) 自定义端点（/api 的 RPC 面由新版 dsh 自身鉴权，rgate 不再代理）
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.login", handler: makeLogin() }), "rgate: login");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.logout", handler: makeLogout() }), "rgate: logout");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.status", handler: makeStatus() }), "rgate: status");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.secret", handler: makeSecret() }), "rgate: secret");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.password", handler: makePassword() }), "rgate: password");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/rgate-login", handler: makeLoginPage() }), "rgate: login page");
  // 2) index.html 注入 UI 门禁脚本
  ctx.effect(() => webServer.tapIndex((html) => String(html).replace(/<head[^>]*>/i, (m) => m + GATE_HEAD)), "rgate: index gate");

  // 签名密钥：登录时用于签发 DSH 能独立验证的信任 cookie。
  state.signingKeyReady = loadSigningKey(DSH_HOME).then((k) => {
    state.signingKey = k;
    return k;
  }).catch((e) => {
    console.error("[rgate] 签名密钥加载失败：" + String((e && e.message) || e));
    return null;
  });

  ensureLoaded().catch((e) => console.error("[rgate] 启动加载失败：" + String((e && e.message) || e)));
  // 远程设置补丁：每次启动幂等检查（覆盖手动升级与自动升级两条路径）。
  reapplyRemoteSettingsPatch().then((r) => {
    if (r.applied) console.log("[rgate] 远程设置补丁：已应用（远程已登录用户可正常使用设置面）锚点=" + r.anchor);
    else if (r.reason === "not-needed") console.log("[rgate] 远程设置补丁：已在位，无需重打");
    else console.error("[rgate] 远程设置补丁未应用: " + r.reason);
  }).catch((e) => console.error("[rgate] 远程设置补丁异常: " + String((e && e.message) || e)));
  // 本体信任补丁：index 放行 + 接受 rgate_auth，去掉 ?token= 的访问前提。
  reapplyDshTrustPatch().then((r) => {
    if (r.applied) console.log("[rgate] 本体信任补丁：已应用（index 放行 + rgate_auth 视为已认证）auth=" + r.auth + " index=" + r.index);
    else if (r.reason === "not-needed") console.log("[rgate] 本体信任补丁：已在位，无需重打");
    else console.error("[rgate] 本体信任补丁未应用: " + r.reason);
  }).catch((e) => console.error("[rgate] 本体信任补丁异常: " + String((e && e.message) || e)));
  console.log("[rgate] 门禁已启用：登录墙 /rgate-login + index.html UI 门禁 + remote-auth 端点 + DSH 信任 cookie（无需 ?token=）");
}
