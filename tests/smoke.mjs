// dsh-rgate smoke test: drive the plugin's real route handlers against a
// stubbed Cordis context inside an isolated HOME — no real credentials touched.
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scryptSync, timingSafeEqual } from "node:crypto";

const FAKE_HOME = mkdtempSync(join(tmpdir(), "dsh-rgate-test-"));
process.env.HOME = FAKE_HOME;

const AUTH_FILE = join(FAKE_HOME, ".dsh", "remote-auth.json");
const TEST_PASSWORD = "smoke-test-password-123";

// Seed a legacy v1 plaintext file so the migration path is exercised.
mkdirSync(join(FAKE_HOME, ".dsh"), { recursive: true });
writeFileSync(AUTH_FILE, JSON.stringify({
  version: 1,
  password: TEST_PASSWORD,
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
}));

const { apply } = await import("../index.js");

const routes = new Map();
const indexTaps = [];

const fakeApiProxy = new Proxy({}, {
  get(_t, domain) {
    if (domain === "respond") return async () => ({ accepted: true });
    if (domain === "downloads") return {
      sessionLog: async () => new Response("FAKEZIP", { status: 200, headers: { "content-type": "application/zip" } }),
    };
    return new Proxy({}, {
      get(_t2, fn) {
        return async (request) => ({ rpcId: request.rpcId, result: { ok: true, value: { fake: domain + "." + fn } } });
      },
    });
  },
});

const ctx = {
  webServer: {
    register(route) { routes.set(route.path, route.handler); return () => routes.delete(route.path); },
    tapIndex(fn) { indexTaps.push(fn); return () => {}; },
  },
  apiProxy: fakeApiProxy,
  get() { return undefined; },
  effect(fn) { return fn(); },
};

function makeReq({ method = "POST", headers = {}, body = null, host = "127.0.0.1:3080", cookie = null }) {
  const req = {
    method,
    headers: { host, ...(cookie ? { cookie } : {}), ...headers },
    socket: { remoteAddress: "127.0.0.1" },
    url: "/",
    _chunks: body === null ? [] : [Buffer.from(body)],
    on(ev, cb) {
      if (ev === "data") { for (const c of this._chunks) cb(c); }
      if (ev === "end") cb();
      return this;
    },
    off() { return this; },
    destroy() {},
  };
  const res = {
    _status: 0, _headers: {}, _body: "",
    writeHead(status, headers) { this._status = status; Object.assign(this._headers, headers || {}); },
    end(text) { this._body += String(text || ""); },
    write(text) { this._body += String(text || ""); },
    writableEnded: false,
  };
  return { req, res };
}

async function call(path, opts = {}) {
  const { req, res } = makeReq(opts);
  req.url = path;
  const handler = routes.get(new URL(path, "http://x").pathname);
  if (!handler) throw new Error("no route for " + path);
  await handler(req, res);
  return { status: res._status, headers: res._headers, body: res._body };
}

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log((cond ? "PASS" : "FAIL") + "  " + label + (cond ? "" : "  <<< " + extra));
  if (!cond) failures += 1;
};

const fileVerify = (password) => {
  const c = JSON.parse(readFileSync(AUTH_FILE, "utf8"));
  if (c.version !== 2 || typeof c.hash !== "string" || typeof c.salt !== "string") return false;
  const expected = Buffer.from(c.hash, "base64");
  const actual = scryptSync(String(password), Buffer.from(c.salt, "base64"), 32, { N: c.N, r: c.r, p: c.p });
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

apply(ctx);

let r;

check("routes registered (60)", routes.size === 60, "size=" + routes.size);

r = await call("/api/session.list", { body: JSON.stringify({ type: "client-request", rpcId: "a1", method: "session.list", payload: {} }), headers: { "content-type": "application/json" } });
check("loopback unary passthrough", r.status === 200 && JSON.parse(r.body).result.ok === true, r.body);

r = await call("/api/session.list", { host: "public.example.com", body: JSON.stringify({ type: "client-request", rpcId: "a2", method: "session.list", payload: {} }), headers: { "content-type": "application/json" } });
check("remote unauthenticated -> 401", r.status === 401, "status=" + r.status);

r = await call("/api/remote-auth.status", { method: "GET", host: "public.example.com" });
const st = JSON.parse(r.body);
check("remote status", r.status === 200 && st.configured === true && st.authenticated === false && st.loopback === false, r.body);

r = await call("/api/remote-auth.secret", { method: "GET" });
const sec = JSON.parse(r.body);
check("loopback secret -> hashed mode, no password", r.status === 200 && sec.mode === "hashed" && sec.password === undefined, r.body);

r = await call("/api/remote-auth.secret", { method: "GET", host: "public.example.com" });
check("remote secret -> 403", r.status === 403);

check("file migrated to v2 scrypt hash", (() => {
  const c = JSON.parse(readFileSync(AUTH_FILE, "utf8"));
  return c.version === 2 && c.algo === "scrypt" && c.password === undefined;
})());
check("legacy password verifies against migrated hash", fileVerify(TEST_PASSWORD));

r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { origin: "https://evil.example", "content-type": "application/json" }, body: JSON.stringify({ password: TEST_PASSWORD }) });
check("cross-site Origin -> 403", r.status === 403, "status=" + r.status);

r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { origin: "https://public.example.com", "content-type": "application/json" }, body: JSON.stringify({ password: "wrong-password-xx" }) });
check("same-origin login proceeds (401 wrong pw)", r.status === 401, "status=" + r.status);

r = await call("/api/remote-auth.logout", { host: "public.example.com", headers: { origin: "https://evil.example" } });
check("logout cross-site Origin -> 403", r.status === 403, "status=" + r.status);

r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: TEST_PASSWORD }) });
const cookie = (r.headers["set-cookie"] || "").split(";")[0];
check("login -> 200 + set-cookie", r.status === 200 && cookie.startsWith("rgate_session="), r.headers["set-cookie"]);

r = await call("/api/settings.describe", { host: "public.example.com", cookie, headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "client-request", rpcId: "a3", method: "settings.describe", payload: {} }) });
check("authenticated settings.describe forwarded", r.status === 200 && JSON.parse(r.body).result.ok === true, r.body);

for (let i = 0; i < 5; i += 1) {
  await call("/api/remote-auth.login", { host: "public.example.com", headers: { "cf-connecting-ip": "1.1.1.1", "content-type": "application/json" }, body: JSON.stringify({ password: "bad" }) });
}
r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { "cf-connecting-ip": "1.1.1.1", "content-type": "application/json" }, body: JSON.stringify({ password: "bad" }) });
check("client A locked after 5 fails -> 429", r.status === 429, "status=" + r.status);

r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { "cf-connecting-ip": "2.2.2.2", "content-type": "application/json" }, body: JSON.stringify({ password: "bad" }) });
check("client B unaffected -> 401 (separate bucket)", r.status === 401, "status=" + r.status);

r = await call("/api/remote-auth.login", { host: "public.example.com", headers: { "cf-connecting-ip": "3.3.3.3", "content-type": "application/json" }, body: JSON.stringify({ password: TEST_PASSWORD }) });
check("client C can still log in -> 200", r.status === 200, "status=" + r.status);

r = await call("/api/remote-auth.password", { host: "public.example.com", cookie, headers: { "content-type": "application/json" }, body: JSON.stringify({ next: "temporary-password-999" }) });
check("remote-authed password change -> 200", r.status === 200 && JSON.parse(r.body).ok === true, r.body);
check("file verifies new password", fileVerify("temporary-password-999"));
check("old password no longer verifies", !fileVerify(TEST_PASSWORD));

r = await call("/api/remote-auth.password", { headers: { "content-type": "application/json" }, body: JSON.stringify({ current: "temporary-password-999", next: TEST_PASSWORD }) });
check("loopback restore -> 200", r.status === 200, r.body);
check("file verifies original password again", fileVerify(TEST_PASSWORD));

r = await call("/rgate-login", { method: "GET", host: "public.example.com" });
check("login page served", r.status === 200 && r.body.includes("/api/remote-auth.login") && r.body.includes("scrypt"), "");

const injected = indexTaps[0]("<html><head><meta charset='utf-8'></head><body></body></html>");
check("gate script injected into head", injected.includes("rgate-gate-style") && injected.includes("/rgate-login") && injected.includes("/api/remote-auth.status"));

console.log(failures === 0 ? "\nALL PASS" : "\n" + failures + " FAILURES");
process.exit(failures === 0 ? 0 : 1);
