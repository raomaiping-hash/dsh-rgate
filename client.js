/**
 * dsh-rgate — 客户端半部
 * 设置页 "远程访问" 分区：状态、登录、登出、改密。
 * 样式注入方式与官方设置分区一致（document.head + data-plugin-css）。
 */
window.__ModuleLoader__.load({
  id: "dsh-rgate",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    var React = require("react");
    var inject = ["slots"];

    // ── CSS：对齐官方 settings-models / settings-plugins 的视觉语言 ──
    var CSS_ID = "dsh-rgate/RemoteAccess.css";
    var CSS = [
      ".rg_section{max-width:560px;color:var(--dsw-alias-label-primary,#1d2126);flex-direction:column;gap:14px;display:flex}",
      ".rg_status{align-items:flex-start;gap:10px;display:flex}",
      ".rg_dot{width:8px;height:8px;border-radius:50%;flex:none;margin-top:7px}",
      ".rg_dotOk{background:var(--dsw-alias-state-success-primary,#2e7d32)}",
      ".rg_dotWarn{background:var(--dsw-alias-state-warn-primary,#b26a00)}",
      ".rg_dotErr{background:var(--dsw-alias-state-error-primary,#c62828)}",
      ".rg_statusTitle{margin:0;font-size:14px;font-weight:500;line-height:22px;color:var(--dsw-alias-label-primary,#1d2126)}",
      ".rg_statusSub{margin:2px 0 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary,#81858c)}",
      ".rg_info{",
      "  margin:0;padding:10px 12px;border-radius:8px;font-size:12px;line-height:18px;",
      "  color:var(--dsw-alias-label-secondary,#61666b);",
      "  background:var(--dsw-alias-bg-module-platform,var(--dsw-alias-bg-layer-2,#f6f7f8));",
      "  border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.12));",
      "}",
      ".rg_alert{margin:0;padding:8px 12px;border-radius:8px;font-size:12px;line-height:18px;border:1px solid}",
      ".rg_alertOk{color:var(--dsw-alias-state-success-primary,#2e7d32);border-color:var(--dsw-alias-state-success-primary,#2e7d32);background:color-mix(in srgb,var(--dsw-alias-state-success-primary,#2e7d32) 8%,transparent)}",
      ".rg_alertErr{color:var(--dsw-alias-state-error-primary,#c62828);border-color:var(--dsw-alias-state-error-primary,#c62828);background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#c62828) 8%,transparent)}",
      ".rg_block{",
      "  border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.12));",
      "  background:var(--dsw-alias-bg-module-platform,var(--dsw-alias-bg-layer-2,#f6f7f8));",
      "  border-radius:12px;padding:14px 16px;flex-direction:column;gap:12px;display:flex;",
      "}",
      ".rg_blockTitle{margin:0;font-size:12px;font-weight:500;line-height:18px;color:var(--dsw-alias-label-secondary,#61666b);letter-spacing:.02em}",
      ".rg_field{flex-direction:column;gap:6px;display:flex;min-width:0}",
      ".rg_label{font-size:12px;font-weight:500;line-height:18px;color:var(--dsw-alias-label-secondary,#61666b)}",
      ".rg_inputWrap{position:relative;display:flex;align-items:center}",
      ".rg_input{",
      "  box-sizing:border-box;width:100%;height:36px;font:inherit;font-size:14px;line-height:22px;",
      "  color:var(--dsw-alias-label-primary,#1d2126);",
      "  background:var(--dsw-alias-bg-layer-1,#fff);",
      "  border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.18));",
      "  border-radius:8px;padding:0 44px 0 12px;outline:none;",
      "}",
      ".rg_input::placeholder{color:var(--dsw-alias-label-dimmed,#a2a6ad)}",
      ".rg_input:focus{border-color:var(--dsw-alias-brand-primary,#2563eb)}",
      ".rg_eye{",
      "  position:absolute;right:4px;top:50%;transform:translateY(-50%);",
      "  height:28px;padding:0 10px;border:none;border-radius:6px;cursor:pointer;font:inherit;font-size:12px;line-height:18px;",
      "  color:var(--dsw-alias-label-tertiary,#81858c);background:transparent;",
      "}",
      ".rg_eye:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(0,0,0,.04));color:var(--dsw-alias-label-secondary,#61666b)}",
      ".rg_grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}",
      "@media (max-width:520px){.rg_grid2{grid-template-columns:1fr}}",
      ".rg_actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:2px}",
      ".rg_btn{",
      "  box-sizing:border-box;height:36px;padding:0 16px;font:inherit;font-size:14px;line-height:22px;",
      "  border-radius:18px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;",
      "  border:none;transition:background .12s ease,opacity .12s ease;",
      "}",
      ".rg_btn:disabled{opacity:.4;cursor:default}",
      ".rg_btn:focus-visible{outline:none;box-shadow:0 0 0 2px var(--dsw-alias-border-l3,rgba(0,0,0,.2))}",
      ".rg_btnPrimary{",
      "  background:var(--dsw-alias-button-primary-fill,var(--dsw-alias-brand-primary,#2563eb));",
      "  color:var(--dsw-alias-label-primary-foreground,#fff);",
      "}",
      ".rg_btnPrimary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover,var(--dsw-alias-brand-primary,#1d4ed8))}",
      ".rg_btnGhost{",
      "  background:transparent;",
      "  color:var(--dsw-alias-label-primary,#1d2126);",
      "  border:1px solid var(--dsw-alias-border-l2,rgba(0,0,0,.18));",
      "}",
      ".rg_btnGhost:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover,rgba(0,0,0,.04))}",
      ".rg_loading{margin:0;font-size:13px;color:var(--dsw-alias-label-tertiary,#81858c)}",
    ].join("");

    if (typeof document !== "undefined" && document.querySelector('style[data-plugin-css="' + CSS_ID + '"]') === null) {
      var tag = document.createElement("style");
      tag.dataset.plugin = "dsh-rgate";
      tag.dataset.pluginCss = CSS_ID;
      tag.textContent = CSS;
      document.head.appendChild(tag);
    }

    function fetchJson(url, init) {
      if (typeof fetch !== "function") return Promise.resolve({ status: 0, data: null });
      return fetch(url, init)
        .then(function (res) {
          return res.text().then(function (text) {
            var data = null;
            try { data = text === "" ? null : JSON.parse(text); } catch (e) {}
            return { status: res.status, data: data };
          });
        })
        .catch(function () {
          return { status: 0, data: null };
        });
    }

    function PasswordField(props) {
      var visibleState = React.useState(false);
      var visible = visibleState[0];
      var setVisible = visibleState[1];
      return React.createElement("div", { className: "rg_field" },
        React.createElement("label", { className: "rg_label" }, props.label),
        React.createElement("div", { className: "rg_inputWrap" },
          React.createElement("input", {
            className: "rg_input",
            type: visible ? "text" : "password",
            placeholder: props.placeholder,
            value: props.value,
            autoComplete: props.autoComplete || "off",
            onChange: function (e) { props.onChange(e.target.value); },
            onKeyDown: props.onKeyDown,
          }),
          React.createElement("button", {
            type: "button",
            className: "rg_eye",
            tabIndex: -1,
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

      React.useEffect(function () { refresh(); }, [refresh]);

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
            setMessage({ tone: "ok", text: "已登录。本浏览器已解锁全部功能。" });
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
            setMessage({ tone: "ok", text: "密码已更新。全部远程会话已失效，请用新密码重新登录。" });
            refresh();
          } else {
            setMessage({ tone: "err", text: String((r.data && r.data.error) || "修改失败。") });
          }
        });
      };

      if (status === null) {
        return React.createElement("div", { className: "rg_section" },
          React.createElement("p", { className: "rg_loading" }, "加载中…"),
        );
      }

      var headTone = "Err";
      var headTitle = "未登录 — 功能被锁定";
      var headSub = "登录后本浏览器将解锁全部功能；密码由本机管理员设置。";
      if (status.loopback) {
        headTone = "Ok";
        headTitle = "本机访问（loopback）";
        headSub = "本机免登录直通，可在此查看存储状态与修改密码。";
      } else if (status.authenticated) {
        headTone = "Ok";
        headTitle = "已登录 — 全部功能已解锁";
        headSub = "会话有效期 7 天；登出或改密后需重新登录。";
      }

      var children = [
        React.createElement("div", { key: "status", className: "rg_status" },
          React.createElement("span", { className: "rg_dot rg_dot" + headTone }),
          React.createElement("div", null,
            React.createElement("p", { className: "rg_statusTitle" }, headTitle),
            React.createElement("p", { className: "rg_statusSub" }, headSub),
          ),
        ),
      ];

      if (message !== null) {
        children.push(React.createElement("p", {
          key: "msg",
          className: "rg_alert rg_alert" + (message.tone === "ok" ? "Ok" : "Err"),
        }, message.text));
      }

      if (secret !== null && secret.path !== undefined) {
        children.push(React.createElement("p", { key: "info", className: "rg_info" },
          "密码以 scrypt 哈希存储于 ",
          React.createElement("code", null, String(secret.path)),
          "，不显示明文。忘记密码：删除该文件并重启服务，新密码会打印在服务日志中。",
        ));
      }

      if (!status.loopback && !status.authenticated) {
        children.push(React.createElement("div", { key: "login", className: "rg_block" },
          React.createElement("p", { className: "rg_blockTitle" }, "登录"),
          React.createElement(PasswordField, {
            label: "访问密码",
            placeholder: "输入访问密码",
            value: loginPw,
            autoComplete: "current-password",
            onChange: setLoginPw,
            onKeyDown: function (e) {
              if (e.key === "Enter") doLogin();
            },
          }),
          React.createElement("div", { className: "rg_actions" },
            React.createElement("button", {
              type: "button",
              className: "rg_btn rg_btnPrimary",
              disabled: busy || loginPw === "",
              onClick: doLogin,
            }, busy ? "登录中…" : "登 录"),
          ),
        ));
      }

      if (status.loopback || status.authenticated) {
        var changeKids = [
          React.createElement("p", { key: "t", className: "rg_blockTitle" }, "修改密码"),
        ];
        if (status.loopback) {
          changeKids.push(React.createElement(PasswordField, {
            key: "cur",
            label: "当前密码",
            placeholder: "输入当前密码",
            value: current,
            autoComplete: "current-password",
            onChange: setCurrent,
          }));
        }
        changeKids.push(React.createElement("div", { key: "grid", className: "rg_grid2" },
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
        ));
        var actions = [
          React.createElement("button", {
            key: "save",
            type: "button",
            className: "rg_btn rg_btnPrimary",
            disabled: busy,
            onClick: doChange,
          }, busy ? "保存中…" : "保存修改"),
        ];
        if (!status.loopback && status.authenticated) {
          actions.push(React.createElement("button", {
            key: "out",
            type: "button",
            className: "rg_btn rg_btnGhost",
            disabled: busy,
            onClick: doLogout,
          }, "登 出"));
        }
        changeKids.push(React.createElement("div", { key: "act", className: "rg_actions" }, actions));
        children.push(React.createElement("div", { key: "change", className: "rg_block" }, changeKids));
      }

      return React.createElement("div", { className: "rg_section" }, children);
    }

    function apply(ctx) {
      ctx.slots.inject("settings.section", function () {
        return ctx.slots.register(
          { name: "settings.section", id: "remote-access", order: 40, label: function () { return "远程访问"; } },
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
