/**
 * dsh-rgate — 客户端半部
 * 设置页新增 "Remote Access" 分区：状态、登录、登出、改密、本机查看密码。
 */
window.__ModuleLoader__.load({
  id: "dsh-rgate",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    var React = require("react");

    var inject = ["slots"];

    var CSS = [
      ".rgate-root { font-family: inherit; line-height: 1.5; }",
      ".rgate-row { display: flex; gap: 8px; align-items: center; margin: 6px 0; flex-wrap: wrap; }",
      ".rgate-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }",
      ".rgate-input { padding: 6px 8px; border-radius: 6px; border: 1px solid rgba(128,128,128,0.55); background: transparent; color: inherit; min-width: 160px; }",
      ".rgate-btn { padding: 6px 14px; border-radius: 6px; border: 1px solid rgba(128,128,128,0.55); background: transparent; color: inherit; cursor: pointer; }",
      ".rgate-btn:hover:not(:disabled) { opacity: 0.8; }",
      ".rgate-btn:disabled { opacity: 0.45; cursor: default; }",
      ".rgate-badge { padding: 2px 10px; border-radius: 999px; font-size: 12px; border: 1px solid rgba(128,128,128,0.55); }",
      ".rgate-ok { color: #2e7d32; }",
      ".rgate-warn { color: #b26a00; }",
      ".rgate-err { color: #c62828; }",
      ".rgate-note { opacity: 0.75; font-size: 12px; margin: 4px 0; }",
    ].join("\n");

    function fetchJson(url, init) {
      if (typeof fetch !== "function") return Promise.resolve({ status: 0, data: null, error: "fetch unavailable" });
      return fetch(url, init)
        .then(function (res) {
          return res.text().then(function (text) {
            var data = null;
            try { data = text === "" ? null : JSON.parse(text); } catch (e) {}
            return { status: res.status, data: data };
          });
        })
        .catch(function (e) {
          return { status: 0, data: null, error: String((e && e.message) || e) };
        });
    }

    function Badge(props) {
      return React.createElement("span", { className: "rgate-badge " + (props.tone || "") }, props.children);
    }

    function inputBox(value, onChange, placeholder) {
      return React.createElement("input", {
        className: "rgate-input",
        type: "password",
        placeholder: placeholder,
        value: value,
        autoComplete: "off",
        onChange: function (e) { onChange(e.target.value); },
      });
    }

    function actionButton(label, onClick, disabled) {
      return React.createElement("button", {
        className: "rgate-btn",
        onClick: onClick,
        disabled: disabled === true,
      }, label);
    }

    function SectionView() {
      var statusState = React.useState(null);
      var status = statusState[0];
      var setStatus = statusState[1];
      var secretState = React.useState(null);
      var secret = secretState[0];
      var setSecret = secretState[1];
      var messageState = React.useState(null);
      var message = messageState[0];
      var setMessage = messageState[1];
      var busyState = React.useState(false);
      var busy = busyState[0];
      var setBusy = busyState[1];
      var loginState = React.useState("");
      var loginPw = loginState[0];
      var setLoginPw = loginState[1];
      var currentState = React.useState("");
      var current = currentState[0];
      var setCurrent = currentState[1];
      var nextState = React.useState("");
      var next = nextState[0];
      var setNext = nextState[1];
      var confirmState = React.useState("");
      var confirm = confirmState[0];
      var setConfirm = confirmState[1];

      var refresh = React.useCallback(function () {
        fetchJson("/api/remote-auth.status").then(function (r) {
          if (r.status === 200 && r.data !== null) setStatus(r.data);
          else setStatus({ configured: false, authenticated: false, loopback: false });
        });
        fetchJson("/api/remote-auth.secret").then(function (r) {
          if (r.status === 200 && r.data !== null) setSecret(r.data);
        });
      }, []);

      React.useEffect(function () {
        refresh();
      }, [refresh]);

      var doLogin = function () {
        if (loginPw === "") return;
        setBusy(true);
        setMessage(null);
        fetchJson("/api/remote-auth.login", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ password: loginPw }),
        }).then(function (r) {
          setBusy(false);
          if (r.status === 200 && r.data !== null && r.data.ok === true) {
            setLoginPw("");
            setMessage({ tone: "rgate-ok", text: "已登录。本浏览器已解锁全部功能（会话、设置、凭据、模型发现）。" });
            refresh();
          } else if (r.status === 429) {
            setMessage({ tone: "rgate-err", text: "尝试次数过多，请 " + String((r.data && r.data.retryInSeconds) || 30) + " 秒后重试。" });
          } else {
            setMessage({ tone: "rgate-err", text: "登录失败。" });
          }
        });
      };

      var doLogout = function () {
        setBusy(true);
        fetchJson("/api/remote-auth.logout", { method: "POST" }).then(function () {
          setBusy(false);
          setMessage({ tone: "rgate-ok", text: "已登出。" });
          refresh();
        });
      };

      var doChange = function () {
        setMessage(null);
        if (next.length < 8) {
          setMessage({ tone: "rgate-err", text: "新密码至少 8 个字符。" });
          return;
        }
        if (next !== confirm) {
          setMessage({ tone: "rgate-err", text: "两次输入的新密码不一致。" });
          return;
        }
        setBusy(true);
        fetchJson("/api/remote-auth.password", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ current: current, next: next }),
        }).then(function (r) {
          setBusy(false);
          if (r.status === 200 && r.data !== null && r.data.ok === true) {
            setCurrent("");
            setNext("");
            setConfirm("");
            setMessage({ tone: "rgate-ok", text: "密码已更新，全部远程会话已失效，请用新密码重新登录。" });
            refresh();
          } else {
            setMessage({ tone: "rgate-err", text: String((r.data && r.data.error) || "修改失败。") });
          }
        });
      };

      if (status === null) return React.createElement("div", { className: "rgate-note" }, "加载中…");

      var rows = [];
      rows.push(React.createElement("div", { key: "h", className: "rgate-row" },
        status.loopback
          ? React.createElement(Badge, { tone: "rgate-ok" }, "本机（loopback）— 免登录直通")
          : status.authenticated
            ? React.createElement(Badge, { tone: "rgate-ok" }, "已登录 — 全部功能已解锁")
            : React.createElement(Badge, { tone: "rgate-warn" }, "未登录 — 功能被锁定"),
      ));

      if (message !== null) rows.push(React.createElement("div", { key: "m", className: "rgate-note " + (message.tone || "") }, message.text));

      if (secret !== null && secret.path !== undefined) {
        rows.push(React.createElement("div", { key: "pw", className: "rgate-row" },
          React.createElement("span", null, "密码存储："),
          React.createElement("code", { className: "rgate-mono" }, String(secret.mode || "hashed")),
          React.createElement("span", { className: "rgate-note" }, "（" + String(secret.path) + "）"),
        ));
        rows.push(React.createElement("div", { key: "pwn", className: "rgate-note" },
          "密码以 scrypt 哈希存储，无法显示。忘记密码：删除服务器上的 ~/.dsh/remote-auth.json 并重启 deepseek-harness 服务，新密码会打印在服务日志中（journalctl -u deepseek-harness | grep rgate）。"));
      }

      if (!status.loopback && !status.authenticated) {
        rows.push(React.createElement("div", { key: "login", className: "rgate-row" },
          inputBox(loginPw, setLoginPw, "访问密码"),
          actionButton("登 录", doLogin, busy || loginPw === ""),
        ));
        rows.push(React.createElement("div", { key: "ln", className: "rgate-note" }, "登录后本浏览器将解锁全部功能；密码由本机管理员设置。"));
      }

      if (status.loopback || status.authenticated) {
        rows.push(React.createElement("div", { key: "ct", className: "rgate-row" }, React.createElement("span", null, "修改密码：")));
        rows.push(React.createElement("div", { key: "chg", className: "rgate-row" },
          status.loopback ? inputBox(current, setCurrent, "当前密码") : null,
          inputBox(next, setNext, "新密码（至少 8 位）"),
          inputBox(confirm, setConfirm, "确认新密码"),
          actionButton("修改", doChange, busy),
        ));
      }

      if (!status.loopback && status.authenticated) {
        rows.push(React.createElement("div", { key: "lo", className: "rgate-row" }, actionButton("登 出", doLogout, busy)));
      }

      return React.createElement("div", { className: "rgate-root" }, rows);
    }

    function apply(ctx) {
      var styles = ctx.get("styles");
      if (styles !== undefined && typeof styles.insert === "function") {
        ctx.effect(function () {
          return styles.insert(CSS);
        }, "rgate: styles");
      }
      ctx.slots.inject("settings.section", function () {
        return ctx.slots.register(
          { name: "settings.section", id: "remote-access", order: 40, label: function () { return "Remote Access"; } },
          function () {
            return React.createElement(SectionView);
          },
        );
      });
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  },
});
