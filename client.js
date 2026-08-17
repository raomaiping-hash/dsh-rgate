/**
 * dsh-rgate — 客户端半部
 * 设置页新增 "Remote Access" 分区：状态、登录、登出、改密、密码存储信息。
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
      ".rgate-card {",
      "  font-family: inherit; line-height: 1.55; color: var(--dsw-alias-label-primary, #1d2126);",
      "  background: var(--dsw-alias-bg-layer-1, #ffffff);",
      "  border: 1px solid var(--dsw-alias-border-l1, rgba(0,0,0,.08));",
      "  border-radius: 12px; padding: 18px 18px 20px; max-width: 560px;",
      "  display: flex; flex-direction: column; gap: 14px;",
      "}",
      ".rgate-head { display: flex; align-items: flex-start; gap: 10px; }",
      ".rgate-dot {",
      "  width: 9px; height: 9px; border-radius: 50%; margin-top: 6px; flex: none;",
      "}",
      ".rgate-dot-ok { background: var(--dsw-alias-state-success-primary, #2e7d32); }",
      ".rgate-dot-warn { background: var(--dsw-alias-state-warn-primary, #b26a00); }",
      ".rgate-dot-err { background: var(--dsw-alias-state-error-primary, #c62828); }",
      ".rgate-title { font-size: 14px; font-weight: 600; }",
      ".rgate-sub { font-size: 12px; color: var(--dsw-alias-label-secondary, #61666b); margin-top: 1px; }",
      ".rgate-block { display: flex; flex-direction: column; gap: 10px; padding-top: 14px; border-top: 1px solid var(--dsw-alias-border-l1, rgba(0,0,0,.08)); }",
      ".rgate-block-title { font-size: 12px; font-weight: 600; letter-spacing: .04em; color: var(--dsw-alias-label-secondary, #61666b); }",
      ".rgate-field { display: flex; flex-direction: column; gap: 5px; }",
      ".rgate-label { font-size: 12px; color: var(--dsw-alias-label-secondary, #61666b); }",
      ".rgate-input-wrap { position: relative; }",
      ".rgate-input {",
      "  width: 100%; box-sizing: border-box; padding: 9px 11px; font-size: 13px;",
      "  color: var(--dsw-alias-label-primary, #1d2126);",
      "  background: var(--dsw-alias-bg-layer-2, #f6f7f8);",
      "  border: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.18)); border-radius: 8px; outline: none;",
      "  transition: border-color .15s ease;",
      "}",
      ".rgate-input:focus { border-color: var(--dsw-alias-brand-primary, #2563eb); }",
      ".rgate-input[data-eye='1'] { padding-right: 44px; }",
      ".rgate-eye {",
      "  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);",
      "  border: none; background: transparent; padding: 4px 8px; font-size: 12px;",
      "  color: var(--dsw-alias-label-secondary, #61666b); cursor: pointer; border-radius: 6px;",
      "}",
      ".rgate-eye:hover { background: var(--dsw-alias-border-l1, rgba(0,0,0,.06)); }",
      ".rgate-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }",
      "@media (max-width: 480px) { .rgate-grid2 { grid-template-columns: 1fr; } }",
      ".rgate-btn {",
      "  border: none; border-radius: 8px; padding: 9px 16px; font-size: 13px; font-weight: 600;",
      "  cursor: pointer; transition: opacity .15s ease; align-self: flex-start;",
      "}",
      ".rgate-btn:disabled { opacity: .45; cursor: default; }",
      ".rgate-btn:not(:disabled):hover { opacity: .86; }",
      ".rgate-btn-primary { color: #fff; background: var(--dsw-alias-brand-primary, #2563eb); }",
      ".rgate-btn-ghost {",
      "  color: var(--dsw-alias-label-primary, #1d2126); background: transparent;",
      "  border: 1px solid var(--dsw-alias-border-l2, rgba(0,0,0,.18));",
      "}",
      ".rgate-alert {",
      "  font-size: 12px; padding: 8px 11px; border-radius: 8px;",
      "  border: 1px solid; line-height: 1.5;",
      "}",
      ".rgate-alert-ok { color: var(--dsw-alias-state-success-primary, #2e7d32); border-color: var(--dsw-alias-state-success-primary, #2e7d32); }",
      ".rgate-alert-warn { color: var(--dsw-alias-state-warn-primary, #b26a00); border-color: var(--dsw-alias-state-warn-primary, #b26a00); }",
      ".rgate-alert-err { color: var(--dsw-alias-state-error-primary, #c62828); border-color: var(--dsw-alias-state-error-primary, #c62828); }",
      ".rgate-info {",
      "  font-size: 12px; color: var(--dsw-alias-label-secondary, #61666b);",
      "  padding: 9px 11px 9px 13px; border-left: 3px solid var(--dsw-alias-brand-primary, #2563eb);",
      "  background: var(--dsw-alias-bg-layer-2, #f6f7f8); border-radius: 0 8px 8px 0; line-height: 1.6;",
      "}",
      ".rgate-hint { font-size: 12px; color: var(--dsw-alias-label-secondary, #61666b); }",
      ".rgate-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }",
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

    function PasswordField(props) {
      var visibleState = React.useState(false);
      var visible = visibleState[0];
      var setVisible = visibleState[1];
      return React.createElement("div", { className: "rgate-field" },
        props.label !== undefined
          ? React.createElement("label", { className: "rgate-label" }, props.label)
          : null,
        React.createElement("div", { className: "rgate-input-wrap" },
          React.createElement("input", {
            className: "rgate-input",
            type: visible ? "text" : "password",
            placeholder: props.placeholder,
            value: props.value,
            autoComplete: props.autoComplete || "off",
            "data-eye": "1",
            onChange: function (e) { props.onChange(e.target.value); },
          }),
          React.createElement("button", {
            type: "button",
            className: "rgate-eye",
            onClick: function () { setVisible(!visible); },
          }, visible ? "隐藏" : "显示"),
        ),
      );
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
            setMessage({ tone: "ok", text: "已登录。本浏览器已解锁全部功能（会话、设置、凭据、模型发现）。" });
            refresh();
          } else if (r.status === 429) {
            setMessage({ tone: "err", text: "尝试次数过多，请 " + String((r.data && r.data.retryInSeconds) || 30) + " 秒后重试。" });
          } else {
            setMessage({ tone: "err", text: "登录失败，请检查密码。" });
          }
        });
      };

      var doLogout = function () {
        setBusy(true);
        fetchJson("/api/remote-auth.logout", { method: "POST" }).then(function () {
          setBusy(false);
          setMessage({ tone: "ok", text: "已登出。" });
          refresh();
        });
      };

      var doChange = function () {
        setMessage(null);
        if (next.length < 8) {
          setMessage({ tone: "err", text: "新密码至少 8 个字符。" });
          return;
        }
        if (next !== confirm) {
          setMessage({ tone: "err", text: "两次输入的新密码不一致。" });
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
            setMessage({ tone: "ok", text: "密码已更新，全部远程会话已失效，请用新密码重新登录。" });
            refresh();
          } else {
            setMessage({ tone: "err", text: String((r.data && r.data.error) || "修改失败。") });
          }
        });
      };

      if (status === null) return React.createElement("div", { className: "rgate-info" }, "加载中…");

      var headTone = "err";
      var headTitle = "未登录 — 功能被锁定";
      var headSub = "登录后本浏览器将解锁全部功能；密码由本机管理员设置。";
      if (status.loopback) {
        headTone = "ok";
        headTitle = "本机访问（loopback）";
        headSub = "本机免登录直通，可在此查看存储状态与修改密码。";
      } else if (status.authenticated) {
        headTone = "ok";
        headTitle = "已登录 — 全部功能已解锁";
        headSub = "会话有效期 7 天；登出或改密后需重新登录。";
      }

      return React.createElement("div", { className: "rgate-card" },
        React.createElement("div", { className: "rgate-head" },
          React.createElement("span", { className: "rgate-dot rgate-dot-" + headTone }),
          React.createElement("div", null,
            React.createElement("div", { className: "rgate-title" }, headTitle),
            React.createElement("div", { className: "rgate-sub" }, headSub),
          ),
        ),

        message !== null
          ? React.createElement("div", { className: "rgate-alert rgate-alert-" + message.tone }, message.text)
          : null,

        secret !== null && secret.path !== undefined
          ? React.createElement("div", { className: "rgate-info" },
              "密码以 scrypt 哈希存储于 " + String(secret.path) + "，出于安全不显示明文。忘记密码：删除该文件并重启 deepseek-harness 服务，新密码会打印在服务日志中（journalctl -u deepseek-harness | grep rgate）。")
          : null,

        !status.loopback && !status.authenticated
          ? React.createElement("div", { className: "rgate-block" },
              React.createElement("div", { className: "rgate-block-title" }, "登录"),
              React.createElement(PasswordField, {
                label: "访问密码",
                placeholder: "输入访问密码",
                value: loginPw,
                autoComplete: "current-password",
                onChange: setLoginPw,
              }),
              React.createElement("button", {
                className: "rgate-btn rgate-btn-primary",
                disabled: busy || loginPw === "",
                onClick: doLogin,
              }, busy ? "登录中…" : "登 录"),
            )
          : null,

        status.loopback || status.authenticated
          ? React.createElement("div", { className: "rgate-block" },
              React.createElement("div", { className: "rgate-block-title" }, "修改密码"),
              status.loopback
                ? React.createElement(PasswordField, {
                    label: "当前密码",
                    placeholder: "输入当前密码",
                    value: current,
                    autoComplete: "current-password",
                    onChange: setCurrent,
                  })
                : null,
              React.createElement("div", { className: "rgate-grid2" },
                React.createElement(PasswordField, {
                  label: "新密码",
                  placeholder: "至少 8 个字符",
                  value: next,
                  autoComplete: "new-password",
                  onChange: setNext,
                }),
                React.createElement(PasswordField, {
                  label: "确认新密码",
                  placeholder: "再次输入新密码",
                  value: confirm,
                  autoComplete: "new-password",
                  onChange: setConfirm,
                }),
              ),
              React.createElement("div", { className: "rgate-actions" },
                React.createElement("button", {
                  className: "rgate-btn rgate-btn-primary",
                  disabled: busy,
                  onClick: doChange,
                }, busy ? "保存中…" : "保存修改"),
                !status.loopback && status.authenticated
                  ? React.createElement("button", {
                      className: "rgate-btn rgate-btn-ghost",
                      disabled: busy,
                      onClick: doLogout,
                    }, "登 出")
                  : null,
              ),
            )
          : null,
      );
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
