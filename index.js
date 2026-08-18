/**
 * dsh-rgate — 远程访问登录门禁（host half）
 *
 * 常驻 Web 插件：对非回环（非 127.0.0.1/localhost/::1）的 Web 访问实施登录墙。
 * - 未登录：任何页面通过 index.html 注入脚本重定向到 /rgate-login 登录页；
 *   全部 /api unary RPC、/api/respond、/api/session.export 返回 401。
 * - 登录成功：HttpOnly + SameSite=Strict cookie（7 天内存会话），放行。
 * - 回环（本机）：始终直通，不要求登录。
 * - 密码存储：~/.dsh/remote-auth.json（0600，明文，与动态版兼容）。
 *
 * 已知边界：/api/events.mux 与 /api/events.host 的 WebSocket 升级由
 * dsh-client-connection 持有，本插件无法在路由层拦截；如需彻底封闭公网
 * 入口，建议在 Cloudflare 控制台为该域名开启 Access（Zero Trust）。
 */
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export const name = "rgate";
export const inject = ["webServer", "apiProxy"];

const COOKIE = "rgate_session";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const REF_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_BODY = 192 * 1024 * 1024; // 与网关默认（160 MiB 图片信封余量）对齐

// 网关 unary 方法表（来自 dsh-host-apiproxy UNARY_ROUTES）
const UNARY = {
  "agentPreset.copy": ["agentPresets", "copy"],
  "agentPreset.list": ["agentPresets", "list"],
  "agentPreset.openDocument": ["agentPresets", "openDocument"],
  "agentPreset.read": ["agentPresets", "read"],
  "agentPreset.remove": ["agentPresets", "remove"],
  "agentPreset.select": ["agentPresets", "select"],
  "credentials.describe": ["credentials", "describe"],
  "credentials.set": ["credentials", "set"],
  "credentials.unset": ["credentials", "unset"],
  "goal.clear": ["goals", "clear"],
  "goal.complete": ["goals", "complete"],
  "goal.create": ["goals", "create"],
  "goal.edit": ["goals", "edit"],
  "goal.pause": ["goals", "pause"],
  "goal.resume": ["goals", "resume"],
  "host.createDirectory": ["host", "createDirectory"],
  "host.describe": ["host", "describe"],
  "host.listDirectory": ["host", "listDirectory"],
  "host.openPath": ["host", "openPath"],
  "host.pickDirectory": ["host", "pickDirectory"],
  "llm.discoverModels": ["llm", "discoverModels"],
  "llm.models": ["llm", "models"],
  "llm.providers": ["llm", "providers"],
  "session.attachment": ["sessions", "attachment"],
  "session.cancel": ["sessions", "cancel"],
  "session.create": ["sessions", "create"],
  "session.fork": ["sessions", "fork"],
  "session.history": ["sessions", "history"],
  "session.list": ["sessions", "list"],
  "session.models": ["sessions", "models"],
  "session.prompt": ["sessions", "prompt"],
  "session.rename": ["sessions", "rename"],
  "session.search": ["sessions", "search"],
  "session.selectModel": ["sessions", "selectModel"],
  "session.updateQueue": ["sessions", "updateQueue"],
  "settings.describe": ["settings", "describe"],
  "settings.mutate": ["settings", "mutate"],
  "settings.openDocument": ["settings", "openDocument"],
  "settings.replace": ["settings", "replace"],
  "settings.update": ["settings", "update"],
  "skill.list": ["skills", "list"],
  "subagent.history": ["subagents", "history"],
  "subagent.interrupt": ["subagents", "interrupt"],
  "subagent.list": ["subagents", "list"],
  "subagent.prompt": ["subagents", "prompt"],
  "workspace.archiveSession": ["workspace", "archiveSession"],
  "workspace.create": ["workspace", "create"],
  "workspace.delete": ["workspace", "delete"],
  "workspace.insertBefore": ["workspace", "insertBefore"],
  "workspace.insertSessionBefore": ["workspace", "insertSessionBefore"],
  "workspace.list": ["workspace", "list"],
  "workspace.rename": ["workspace", "rename"],
};

// 敏感配置面：结构性校验（与网关 zod 边界对齐）
const STRICT = {
  "settings.describe": (p) => p !== null && typeof p === "object" && !Array.isArray(p),
  "settings.update": (p) => p !== null && typeof p === "object" && typeof p.ns === "string" && p.ns.length > 0 &&
    p.patch !== null && typeof p.patch === "object" && !Array.isArray(p.patch) &&
    (p.expectedRevision === undefined || Number.isInteger(p.expectedRevision)),
  "settings.replace": (p) => p !== null && typeof p === "object" && typeof p.ns === "string" && p.ns.length > 0 &&
    p.section !== null && typeof p.section === "object" && !Array.isArray(p.section) &&
    (p.expectedRevision === undefined || Number.isInteger(p.expectedRevision)),
  "settings.mutate": (p) => p !== null && typeof p === "object" && typeof p.ns === "string" && p.ns.length > 0 &&
    Array.isArray(p.ops) && p.ops.every((op) => op !== null && typeof op === "object" &&
      (op.op === "set" || op.op === "unset") && Array.isArray(op.path)) &&
    (p.expectedRevision === undefined || Number.isInteger(p.expectedRevision)),
  "credentials.describe": (p) => p !== null && typeof p === "object" && Array.isArray(p.refs) && p.refs.length <= 64 &&
    p.refs.every((r) => typeof r === "string" && REF_PATTERN.test(r)),
  "credentials.set": (p) => p !== null && typeof p === "object" && typeof p.ref === "string" && REF_PATTERN.test(p.ref) &&
    typeof p.value === "string" && p.value.length >= 1,
  "credentials.unset": (p) => p !== null && typeof p === "object" && typeof p.ref === "string" && REF_PATTERN.test(p.ref),
  "agentPreset.read": (p) => p !== null && typeof p === "object" && typeof p.agentPreset === "string" && p.agentPreset.length > 0,
  "agentPreset.copy": (p) => p !== null && typeof p === "object" && typeof p.from === "string" && p.from.length > 0 &&
    typeof p.agentPreset === "string" && p.agentPreset.length > 0 && (p.name === undefined || typeof p.name === "string"),
  "llm.discoverModels": (p) => p !== null && typeof p === "object" && typeof p.settingsNs === "string" && p.settingsNs.length > 0,
};

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
  // makes a protected RPC return our marker, go straight back to the login wall
  // instead of leaving the app on a bare 401 error.
  var nativeFetch = window.fetch;
  if (typeof nativeFetch === "function") {
    window.fetch = function () {
      return nativeFetch.apply(this, arguments).then(function (response) {
        if (response.status === 401 && response.headers.get("x-rgate-auth") === "required") loginPage();
        return response;
      });
    };
  }
  function show() {
    var el = document.getElementById("rgate-gate-style");
    if (el) el.remove();
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

export function apply(ctx) {
  const webServer = ctx.webServer;
  const apiProxy = ctx.apiProxy;
  if (webServer === undefined || apiProxy === undefined) {
    console.error("[rgate] webServer 或 apiProxy 不可用，门禁未启用");
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

  const abortSignal = (req) => {
    const controller = new AbortController();
    const onClose = () => controller.abort();
    req.on("close", onClose);
    const done = () => req.off("close", onClose);
    return { signal: controller.signal, done };
  };

  const badEnvelope = (res, rpcId, message) => sendJson(res, 200, {
    type: "server-response",
    rpcId,
    result: { ok: false, error: { code: "bad-request", message, details: { issues: [] } } },
  });

  const makeGate = (method, domain, fn) => async (req, res) => {
    await ensureLoaded();
    if (!allowed(req)) {
      sendUnauthorized(res);
      return;
    }
    if (req.method !== "POST") {
      sendPlain(res, 404, "not found");
      return;
    }
    const ct = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/json") {
      sendPlain(res, 415, "content type must be application/json");
      return;
    }
    let bodyText;
    try {
      bodyText = await readBody(req);
    } catch (e) {
      sendPlain(res, 400, "body is not JSON");
      return;
    }
    let body;
    try {
      body = JSON.parse(bodyText);
    } catch (e) {
      sendPlain(res, 400, "body is not JSON");
      return;
    }
    const rpcId = body !== null && typeof body === "object" && typeof body.rpcId === "string" ? body.rpcId : "invalid-request";
    if (body === null || typeof body !== "object" || body.type !== "client-request") return badEnvelope(res, rpcId, "invalid client-request message");
    if (body.method !== method) return badEnvelope(res, rpcId, `method "${String(body.method)}" does not match path "${method}"`);
    const validate = STRICT[method] || ((p) => p !== null && typeof p === "object" && !Array.isArray(p));
    if (!validate(body.payload)) return badEnvelope(res, rpcId, `invalid payload for ${method}`);
    try {
      const { signal, done } = abortSignal(req);
      const narrow = await apiProxy[domain][fn]({ rpcId, payload: body.payload }, signal);
      done();
      sendJson(res, 200, { type: "server-response", rpcId: narrow.rpcId, result: narrow.result });
    } catch (e) {
      sendPlain(res, 500, "handler failure: " + String((e && e.message) || e));
    }
  };

  const makeRespond = () => async (req, res) => {
    await ensureLoaded();
    if (!allowed(req)) {
      sendUnauthorized(res);
      return;
    }
    if (req.method !== "POST") {
      sendPlain(res, 404, "not found");
      return;
    }
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch (e) {
      sendPlain(res, 400, "body is not JSON");
      return;
    }
    if (body === null || typeof body !== "object" || body.type !== "client-response" || typeof body.rpcId !== "string") {
      sendJson(res, 200, { accepted: false, reason: "bad-response" });
      return;
    }
    try {
      sendJson(res, 200, await apiProxy.respond(body));
    } catch (e) {
      sendPlain(res, 500, "handler failure: " + String((e && e.message) || e));
    }
  };

  const makeExport = () => async (req, res) => {
    await ensureLoaded();
    if (!allowed(req)) {
      sendUnauthorized(res);
      return;
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      sendPlain(res, 404, "not found");
      return;
    }
    const url = new URL(req.url, "http://localhost");
    const sessionId = url.searchParams.get("sessionId");
    if (sessionId === null || sessionId === "") {
      sendPlain(res, 400, "missing or invalid sessionId query parameter");
      return;
    }
    try {
      const { signal, done } = abortSignal(req);
      const response = await apiProxy.downloads.sessionLog({
        sessionId,
        includeDescendants: url.searchParams.get("includeDescendants") === "true",
      }, signal);
      done();
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });
      res.writeHead(response.status, headers);
      if (req.method === "HEAD") {
        if (response.body && typeof response.body.cancel === "function") await response.body.cancel().catch(() => {});
        res.end();
        return;
      }
      if (response.body !== null && response.body !== undefined) {
        for await (const chunk of response.body) {
          res.write(Buffer.from(chunk));
        }
      }
      res.end();
    } catch (e) {
      if (!res.writableEnded) sendPlain(res, 500, "export failed: " + String((e && e.message) || e));
    }
  };

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
      state.sessions.set(token, Date.now() + SESSION_TTL_MS);
      console.log("[rgate] 登录成功：" + key);
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
        "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
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
      "set-cookie": `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
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
        "set-cookie": `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
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

  // 1) 全部 unary RPC 精确路由（遮蔽 /api 前缀）
  for (const method of Object.keys(UNARY)) {
    const [domain, fn] = UNARY[method];
    ctx.effect(() => webServer.register({ kind: "exact", path: "/api/" + method, handler: makeGate(method, domain, fn) }), "rgate: " + method);
  }
  // 2) 应答与导出面
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/respond", handler: makeRespond() }), "rgate: respond");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/session.export", handler: makeExport() }), "rgate: session.export");
  // 3) 自定义端点
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.login", handler: makeLogin() }), "rgate: login");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.logout", handler: makeLogout() }), "rgate: logout");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.status", handler: makeStatus() }), "rgate: status");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.secret", handler: makeSecret() }), "rgate: secret");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/api/remote-auth.password", handler: makePassword() }), "rgate: password");
  ctx.effect(() => webServer.register({ kind: "exact", path: "/rgate-login", handler: makeLoginPage() }), "rgate: login page");
  // 4) index.html 注入 UI 门禁脚本
  ctx.effect(() => webServer.tapIndex((html) => String(html).replace(/<head[^>]*>/i, (m) => m + GATE_HEAD)), "rgate: index gate");

  ensureLoaded().catch((e) => console.error("[rgate] 启动加载失败：" + String((e && e.message) || e)));
  console.log("[rgate] 门禁已启用：登录墙 /rgate-login + 52 个 unary RPC + respond + session.export 全部受保护");
}
