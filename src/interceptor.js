"use strict";
/** Explicit call-site interception. Never replaces Electron's global security handlers. */
const electron = require("electron");
const fs = require("fs");
const path = require("path");
const INTERCEPTOR_VERSION = "1.3.0";

function getStorageDir() {
    const appData = process.env.APPDATA || (process.platform === "darwin"
        ? path.join(process.env.HOME || "", "Library", "Application Support")
        : path.join(process.env.HOME || "", ".config"));
    return path.join(appData, "Antigravity");
}

function readConfig() {
    try {
        const config = JSON.parse(fs.readFileSync(path.join(getStorageDir(), "interceptor_config.json"), "utf-8"));
        return config && typeof config === "object" && !Array.isArray(config) ? config : {};
    } catch (_) { return {}; }
}

function isInterceptionEnabled() { return readConfig().enabled !== false; }

function isOAuthUrl(url) {
    if (typeof url !== "string" || url.length > 8192 || /[\u0000-\u001f]/.test(url) || /%(?![0-9A-Fa-f]{2})/.test(url)) return false;
    try {
        // Check the raw route too: WHATWG URL normalizes dot-segments and backslashes.
        if (!/^https:\/\/accounts\.google\.com(?::443)?\/o\/oauth2\/(v2\/)?auth\?/i.test(url)) return false;
        const u = new URL(url);
        if (u.protocol !== "https:" || u.hostname !== "accounts.google.com" || u.port
            || u.username || u.password || u.hash || !/^\/o\/oauth2\/(v2\/)?auth$/.test(u.pathname)) return false;
        const names = [...u.searchParams.keys()];
        if (names.length > 100 || new Set(names).size !== names.length) return false;
        if (u.searchParams.get("response_type") !== "code" || !u.searchParams.get("state")
            || !u.searchParams.get("code_challenge")) return false;
        const redirect = u.searchParams.get("redirect_uri") || "";
        if (!/^http:\/\/(localhost|127\.0\.0\.1):[0-9]{1,5}\/auth\/callback$/i.test(redirect)) return false;
        const ru = new URL(redirect);
        const port = Number(redirect.match(/:([0-9]+)\/auth\/callback$/)[1]);
        return port >= 1 && port <= 65535 && ru.pathname === "/auth/callback";
    } catch (_) { return false; }
}

function shouldCapture(url) {
    // capture_all from older versions is deliberately ignored: ordinary links stay ordinary.
    return isInterceptionEnabled() && isOAuthUrl(url);
}

async function handleCapturedUrl(url, reason, options) {
    if (!shouldCapture(url)) return electron.shell.openExternal(url, options);
    const dir = getStorageDir();
    const payload = { url, timestamp: new Date().toISOString(), time: Date.now(), version: INTERCEPTOR_VERSION };
    // Only the latest authorization request is stored for the companion UI; no URL history or HTTP broadcast.
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "captured_url.json"), JSON.stringify(payload, null, 2), { encoding: "utf-8", mode: 0o600 });
    try { electron.clipboard.writeText(url); } catch (_) { /* Companion UI can still copy the capture. */ }
}

module.exports = { handleCapturedUrl, isOAuthUrl, shouldCapture, isInterceptionEnabled };
