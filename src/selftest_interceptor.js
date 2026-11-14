"use strict";
// 所有 I/O 均在 vm 沙箱内模拟，不读写真实用户目录，也不访问网络。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { URL, URLSearchParams } = require("node:url");
const source = fs.readFileSync(path.join(__dirname, "interceptor.js"), "utf8");

function oauth(overrides = {}, pathname = "/o/oauth2/v2/auth") {
    const params = new URLSearchParams({
        client_id: "fixture.apps.googleusercontent.com",
        response_type: "code",
        state: "fixture-state-1234567890",
        code_challenge: "A".repeat(43),
        code_challenge_method: "S256",
        redirect_uri: "http://localhost:43891/auth/callback",
        scope: "openid email profile",
        ...overrides,
    });
    return `https://accounts.google.com${pathname}?${params}`;
}

function sandbox(config = {}) {
    const files = new Map();
    const writes = [];
    const clipboard = [];
    const opens = [];
    const hooks = [];
    const network = [];
    const logs = [];
    const storage = path.join("C:/mock-roaming", "Antigravity");
    const normalize = value => path.normalize(String(value));
    const configPath = normalize(path.join(storage, "interceptor_config.json"));
    const rawOpen = function (...args) {
        opens.push({ self: this, args });
        return Promise.resolve("shell-result");
    };
    const shell = { openExternal: rawOpen };
    const electron = {
        shell,
        clipboard: { writeText: text => clipboard.push(text) },
        app: { on: (...args) => hooks.push(args), once: (...args) => hooks.push(args),
               getPath: () => storage },
        BrowserWindow: { getAllWindows: () => [] },
    };
    const mockFs = {
        existsSync: filename => normalize(filename) === configPath || files.has(normalize(filename)),
        readFileSync: filename => {
            if (normalize(filename) === configPath) return JSON.stringify(config);
            const data = files.get(normalize(filename));
            if (data === undefined) throw new Error("模拟文件不存在");
            return data;
        },
        mkdirSync: (filename, options) => writes.push({ type: "mkdir", filename: normalize(filename), options }),
        writeFileSync: (filename, data) => {
            const key = normalize(filename);
            writes.push({ type: "write", filename: key, data: String(data) });
            files.set(key, String(data));
        },
        appendFileSync: (filename, data) => writes.push({ type: "append", filename: normalize(filename), data: String(data) }),
        renameSync: (from, to) => {
            writes.push({ type: "rename", filename: normalize(to) });
            files.set(normalize(to), files.get(normalize(from)));
            files.delete(normalize(from));
        },
        unlinkSync: filename => files.delete(normalize(filename)),
    };
    const mockHttp = new Proxy({}, { get: (_target, method) => (...args) => {
        network.push({ method, args });
        return { on() { return this; }, write() {}, end() {}, destroy() {} };
    } });
    const module = { exports: {} };
    const context = {
        module, exports: module.exports, URL, URLSearchParams, Buffer,
        process: { env: { APPDATA: "C:/mock-roaming", HOME: "C:/mock-home" }, platform: "win32", pid: 1234 },
        console: Object.fromEntries(["log", "warn", "error", "info"].map(key => [key, (...args) => logs.push(args.join(" "))])),
        setTimeout, clearTimeout,
        require: name => {
            if (name === "electron") return electron;
            if (name === "fs" || name === "node:fs") return mockFs;
            if (name === "path" || name === "node:path") return path;
            if (["http", "https", "node:http", "node:https"].includes(name)) return mockHttp;
            throw new Error(`禁止未模拟模块：${name}`);
        },
        fetch: (...args) => { network.push({ method: "fetch", args }); return Promise.reject(new Error("禁止网络")); },
    };
    vm.runInNewContext(source, context, { filename: "interceptor.js", timeout: 3000 });
    return { api: module.exports, context, electron, rawOpen, files, writes, clipboard, opens, hooks, network, logs, storage };
}

function noSideEffects(state) {
    assert.equal(state.writes.length, 0, "不应写文件或目录");
    assert.equal(state.clipboard.length, 0, "不应更新剪贴板");
    assert.equal(state.network.length, 0, "不应发起网络请求");
}

const cases = [];
const test = (name, fn) => cases.push({ name, fn });

test("加载模块不替换 shell、不安装全局事件或写文件", () => {
    const s = sandbox();
    assert.equal(s.electron.shell.openExternal, s.rawOpen);
    assert.equal(Object.hasOwn(s.electron.shell, "__rawOpenExternal"), false);
    assert.equal(s.hooks.length, 0);
    noSideEffects(s);
    assert.equal(typeof s.api.handleCapturedUrl, "function");
});

test("合法 Google PKCE 链接仅保存 captured_url.json 与剪贴板", async () => {
    const s = sandbox();
    const url = oauth();
    const result = s.api.handleCapturedUrl(url, "externalUrl");
    assert.equal(typeof result?.then, "function", "显式调用必须返回 Promise");
    await result;
    assert.deepEqual(s.clipboard, [url]);
    assert.equal(s.opens.length, 0);
    assert.equal(s.network.length, 0);
    assert.equal(s.files.size, 1);
    const filename = path.normalize(path.join(s.storage, "captured_url.json"));
    const payload = JSON.parse(s.files.get(filename));
    assert.equal(payload.url, url);
    assert.ok(Number.isFinite(payload.time));
    assert.ok(!Number.isNaN(Date.parse(payload.timestamp)));
    for (const write of s.writes) {
        if (write.type !== "mkdir") {
            assert.ok(write.filename.endsWith("captured_url.json") || write.filename.endsWith("captured_url.json.tmp"));
        }
        assert.notEqual(write.type, "append", "不写历史日志");
    }
    assert.ok(!s.logs.some(line => line.includes(url) || line.includes("fixture-state")), "控制台不能泄露授权 URL 或 state");
});

test("普通外链逐字透传原 shell 并返回 Promise", async () => {
    const s = sandbox();
    const url = "https://Example.COM/Some%2fPath?q=A%2BB&secret=fixture#MixedCase";
    const result = s.api.handleCapturedUrl(url, "externalUrl");
    assert.equal(typeof result?.then, "function");
    await result;
    assert.equal(s.opens.length, 1);
    assert.equal(s.opens[0].args[0], url);
    assert.equal(s.opens[0].self, s.electron.shell);
    noSideEffects(s);
    assert.ok(!s.logs.some(line => line.includes(url)), "普通外链不得进入日志");
});

test("普通外链 options 与原 shell 返回值保持不变", async () => {
    const s = sandbox();
    const options = { activate: false };
    const value = await s.api.handleCapturedUrl("https://example.com/options", "externalUrl", options);
    assert.equal(value, "shell-result");
    assert.equal(s.opens[0].args[1], options);
    noSideEffects(s);
});

test("暂停时授权链接原样放行且不捕获", async () => {
    const s = sandbox({ enabled: false });
    const url = oauth();
    assert.equal(s.api.shouldCapture(url), false);
    await s.api.handleCapturedUrl(url, "externalUrl");
    assert.equal(s.opens.length, 1);
    assert.equal(s.opens[0].args[0], url);
    noSideEffects(s);
});

test("capture_all 旧配置不能扩大捕获范围", async () => {
    const s = sandbox({ enabled: true, capture_all: true });
    const url = "https://example.com/not-auth";
    assert.equal(s.api.shouldCapture(url), false);
    await s.api.handleCapturedUrl(url, "externalUrl");
    assert.equal(s.opens[0].args[0], url);
    noSideEffects(s);
});

for (const redirect of ["http://localhost:43891/auth/callback", "http://127.0.0.1:43891/auth/callback"]) {
    test(`合法回环回调：${redirect}`, () => {
        const s = sandbox();
        assert.equal(s.api.isOAuthUrl(oauth({ redirect_uri: redirect })), true);
    });
}
for (const pathname of ["/o/oauth2/auth", "/o/oauth2/v2/auth"]) {
    test(`Google 授权入口：${pathname}`, () => assert.equal(sandbox().api.isOAuthUrl(oauth({}, pathname)), true));
}

test("搬运不改变客户端的 PKCE 算法选择", () => {
    assert.equal(sandbox().api.isOAuthUrl(oauth({ code_challenge_method: "plain" })), true);
});

const invalid = [
    ["缺 state", oauth({ state: "" })],
    ["缺 PKCE", oauth({ code_challenge: "" })],
    ["IPv6 不在 IPv4 搬运范围", oauth({ redirect_uri: "http://[::1]:43891/auth/callback" })],
    ["原始路径 dot-segment", oauth().replace("/o/oauth2/v2/auth?", "/ignored/../o/oauth2/v2/auth?")],
    ["非 code 流程", oauth({ response_type: "token" })],
    ["非 https", oauth().replace("https://", "http://")],
    ["Google 相似域名", oauth().replace("accounts.google.com", "accounts.google.com.evil.example")],
    ["凭据伪装", oauth().replace("accounts.google.com", "accounts.google.com@evil.example")],
    ["URL 用户信息", oauth().replace("https://", "https://user:password@")],
    ["Google 非默认端口", oauth().replace("accounts.google.com", "accounts.google.com:444")],
    ["错误授权路径", oauth({}, "/o/oauth2/v2/auth/evil")],
    ["回调外网域名", oauth({ redirect_uri: "http://evil.example:43891/auth/callback" })],
    ["localhost 相似域名", oauth({ redirect_uri: "http://localhost.evil.example:43891/auth/callback" })],
    ["回调端口零", oauth({ redirect_uri: "http://localhost:0/auth/callback" })],
    ["回调端口越界", oauth({ redirect_uri: "http://localhost:65536/auth/callback" })],
    ["回调端口非数字", oauth({ redirect_uri: "http://localhost:bad/auth/callback" })],
    ["回调缺端口", oauth({ redirect_uri: "http://localhost/auth/callback" })],
    ["回调 https", oauth({ redirect_uri: "https://localhost:43891/auth/callback" })],
    ["错误回调路径", oauth({ redirect_uri: "http://localhost:43891/other" })],
    ["回调查询串", oauth({ redirect_uri: "http://localhost:43891/auth/callback?x=1" })],
    ["回调片段", oauth({ redirect_uri: "http://localhost:43891/auth/callback#fragment" })],
    ["回调凭据", oauth({ redirect_uri: "http://user@localhost:43891/auth/callback" })],
    ["无效 percent 编码", oauth() + "&x=%ZZ"],
    ["畸形 URL", "https://[invalid"],
    ["URL 片段", oauth() + "#fragment"],
];
for (const key of ["state", "redirect_uri", "response_type", "code_challenge", "client_id", "scope"]) {
    const good = new URL(oauth());
    invalid.push([`重复参数 ${key}`, oauth() + "&" + new URLSearchParams({ [key]: good.searchParams.get(key) })]);
}
for (const [name, url] of invalid) {
    test(`拒绝捕获：${name}`, async () => {
        const s = sandbox();
        assert.equal(s.api.isOAuthUrl(url), false);
        assert.equal(s.api.shouldCapture(url), false);
        await s.api.handleCapturedUrl(url, "externalUrl");
        assert.equal(s.opens.length, 1);
        assert.equal(s.opens[0].args[0], url, "未捕获的输入保持显式调用原行为");
        noSideEffects(s);
    });
}

test("无效类型不会被识别成授权", () => {
    const s = sandbox();
    for (const value of [null, undefined, 123, {}, "", "x".repeat(9000)]) {
        assert.equal(s.api.isOAuthUrl(value), false);
    }
});

test("直接调用原 shell 不会触发捕获", async () => {
    const s = sandbox();
    await s.electron.shell.openExternal(oauth());
    assert.equal(s.opens.length, 1);
    noSideEffects(s);
});

test("原 shell 拒绝以 Promise 错误传给调用者", async () => {
    const s = sandbox();
    s.electron.shell.openExternal = () => Promise.reject(new Error("模拟系统拒绝"));
    await assert.rejects(Promise.resolve(s.api.handleCapturedUrl("https://example.com/", "externalUrl")), /模拟系统拒绝/);
    noSideEffects(s);
});

(async () => {
    let passed = 0;
    const failed = [];
    for (const item of cases) {
        try {
            await item.fn();
            passed++;
            console.log(`OK ${item.name}`);
        } catch (error) {
            failed.push(item.name);
            console.error(`FAIL ${item.name}\n${error.stack || error}`);
        }
    }
    console.log(`JS 回归：通过 ${passed} 项，失败 ${failed.length} 项，总计 ${cases.length} 项`);
    process.exitCode = failed.length ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
