"use strict";

/* Hunt Containers - background
 *
 * Routing model:
 *   request -> tabId -> explicit tab binding      (session scoped, popup toggle)
 *           -> tabId -> cookieStoreId -> container binding (persisted)
 *           -> no binding -> DIRECT
 *
 * Fail-closed note: Firefox does NOT silently fall back to direct when a bound
 * proxy is unreachable - the request errors. That is the desired behaviour: a
 * dead proxy must never leak your real egress IP onto a program's target.
 */

const api = globalThis.browser ?? globalThis.chrome;

const CAP = {
  perRequest:  !!(api.proxy && api.proxy.onRequest),      // Firefox
  containers:  !!api.contextualIdentities,                // Firefox
  globalProxy: !!(api.proxy && api.proxy.settings),       // Chrome
};

const S = {
  profiles: [],        // proxy configs
  presets: [],         // one-click program launchers
  containerBind: {},   // cookieStoreId -> profileId   (persisted)
  tabBind: {},         // tabId         -> profileId   (session only)
  settings: { ipCheckUrl: "https://api.ipify.org?format=json" },
};

const tabStore = new Map();   // tabId -> cookieStoreId

// ------------------------------------------------------------------ storage
const KEYS = ["profiles", "presets", "containerBind", "settings"];

async function load() {
  const d = await api.storage.local.get(KEYS);
  S.profiles      = d.profiles      ?? [];
  S.presets       = d.presets       ?? [];
  S.containerBind = d.containerBind ?? {};
  S.settings      = Object.assign(S.settings, d.settings ?? {});

  // Tab bindings must survive event-page suspension. MV3 background pages are
  // non-persistent: if these lived only in memory, a suspended-then-woken worker
  // would resolve a bound tab to DIRECT and leak your real IP onto the target.
  try {
    const sess = await api.storage.session.get("tabBind");
    S.tabBind = sess.tabBind ?? {};
  } catch (_) { S.tabBind = {}; }
}

async function saveSession() {
  try { await api.storage.session.set({ tabBind: S.tabBind }); } catch (_) {}
}

async function save() {
  await api.storage.local.set({
    profiles: S.profiles,
    presets: S.presets,
    containerBind: S.containerBind,
    settings: S.settings,
  });
}

api.storage.onChanged.addListener((ch, area) => {
  if (area !== "local") return;
  if (ch.profiles)      S.profiles      = ch.profiles.newValue      ?? [];
  if (ch.presets)       S.presets       = ch.presets.newValue       ?? [];
  if (ch.containerBind) S.containerBind = ch.containerBind.newValue ?? {};
  if (ch.settings)      S.settings      = ch.settings.newValue      ?? S.settings;
});

// -------------------------------------------------------------- tab tracking
async function primeTabs() {
  try {
    for (const t of await api.tabs.query({})) {
      if (t.cookieStoreId) tabStore.set(t.id, t.cookieStoreId);
    }
  } catch (_) {}
}

api.tabs.onCreated.addListener(t => {
  if (t.cookieStoreId) tabStore.set(t.id, t.cookieStoreId);
});
api.tabs.onRemoved.addListener(id => {
  tabStore.delete(id);
  if (S.tabBind[id]) { delete S.tabBind[id]; saveSession(); }
});

// ------------------------------------------------------------------ resolve
function profileById(id) {
  return S.profiles.find(p => p.id === id) || null;
}

function resolveProfile(details) {
  const tabId = details.tabId;
  if (tabId == null || tabId < 0) return null;          // system / bg request

  const direct = S.tabBind[tabId];
  if (direct) return profileById(direct);

  const csid = details.cookieStoreId || tabStore.get(tabId);
  if (csid && S.containerBind[csid]) return profileById(S.containerBind[csid]);

  return null;
}

function toProxyInfo(p) {
  if (!p || p.kind === "direct" || !p.host) return { type: "direct" };

  const type = p.kind === "socks5" ? "socks"
             : p.kind === "socks4" ? "socks4"
             : p.kind;                                    // "http" | "https"

  const info = { type, host: String(p.host).trim(), port: Number(p.port) };

  if (type === "socks" || type === "socks4") {
    // resolve DNS at the proxy - stops your resolver leaking the target
    info.proxyDNS = p.proxyDNS !== false;
  }
  if (p.username) {
    info.username = p.username;
    info.password = p.password || "";
    if (type === "http" || type === "https") {
      info.proxyAuthorizationHeader =
        "Basic " + btoa(`${p.username}:${p.password || ""}`);
    }
  }
  return info;
}

// ------------------------------------------------------------- proxy routing
if (CAP.perRequest) {
  api.proxy.onRequest.addListener(
    details => toProxyInfo(resolveProfile(details)),
    { urls: ["<all_urls>"] }
  );

  if (api.proxy.onError) {
    api.proxy.onError.addListener(err => console.warn("[hunt] proxy error", err));
  }
}

// --------------------------------------------------- per-profile header set
// Static, operator-declared headers only. Used for program-mandated markers
// (e.g. X-Bug-Bounty: <handle>) that policies require on every request.
if (api.webRequest && api.webRequest.onBeforeSendHeaders) {
  api.webRequest.onBeforeSendHeaders.addListener(
    details => {
      const p = resolveProfile(details);
      if (!p || !Array.isArray(p.headers) || !p.headers.length) return {};

      const headers = details.requestHeaders || [];
      for (const h of p.headers) {
        if (!h || !h.name) continue;
        const name = h.name.trim();
        const i = headers.findIndex(x => x.name.toLowerCase() === name.toLowerCase());
        if (i >= 0) headers[i].value = h.value ?? "";
        else headers.push({ name, value: h.value ?? "" });
      }
      return { requestHeaders: headers };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"]
  );
}

// --------------------------------------------------------- proxy auth (401)
if (api.webRequest && api.webRequest.onAuthRequired) {
  const seen = new Set();
  api.webRequest.onAuthRequired.addListener(
    details => {
      if (!details.isProxy) return {};
      if (seen.has(details.requestId)) return {};   // don't loop on bad creds
      const p = resolveProfile(details);
      if (!p || !p.username) return {};
      seen.add(details.requestId);
      setTimeout(() => seen.delete(details.requestId), 30000);
      return { authCredentials: { username: p.username, password: p.password || "" } };
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
  );
}

// ------------------------------------------------------------------ helpers
function waitForComplete(tabId, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error("timeout")); }, ms);
    function onUpd(id, info) {
      if (id === tabId && info.status === "complete") { cleanup(); resolve(); }
    }
    function cleanup() { clearTimeout(timer); api.tabs.onUpdated.removeListener(onUpd); }
    api.tabs.onUpdated.addListener(onUpd);
  });
}

async function readTabText(tabId) {
  const out = await api.scripting.executeScript({
    target: { tabId },
    func: () => (document.body ? document.body.innerText.slice(0, 400) : ""),
  });
  return (out && out[0] && out[0].result) || "";
}

/* Reachability + egress-IP check for one profile.
 * Opens a throwaway background tab bound to the profile, hits the IP echo
 * service through it, reads the answer, closes the tab. This measures the
 * real route, not a guess. It does not touch any target. */
async function testProfile(profileId) {
  const started = Date.now();
  let tab;
  try {
    tab = await api.tabs.create({ url: "about:blank", active: false });
    S.tabBind[tab.id] = profileId;
    await saveSession();
    await api.tabs.update(tab.id, { url: S.settings.ipCheckUrl });
    await waitForComplete(tab.id, 25000);
    const body = await readTabText(tab.id);
    let ip = null;
    try { ip = JSON.parse(body).ip; } catch (_) { ip = (body.match(/[0-9a-f.:]{7,}/i) || [])[0] || null; }
    return { ok: true, ms: Date.now() - started, ip, body };
  } catch (e) {
    return { ok: false, ms: Date.now() - started, error: String(e && e.message || e) };
  } finally {
    if (tab) {
      delete S.tabBind[tab.id]; await saveSession();
      try { await api.tabs.remove(tab.id); } catch (_) {}
    }
  }
}

async function ensureContainer(name, color, icon) {
  if (!CAP.containers) return null;
  const existing = await api.contextualIdentities.query({ name });
  if (existing.length) return existing[0];
  return api.contextualIdentities.create({
    name,
    color: color || "blue",
    icon: icon || "briefcase",
  });
}

/* Preset launcher: container + proxy binding + start URL, in one click. */
async function launchPreset(presetId) {
  const preset = S.presets.find(p => p.id === presetId);
  if (!preset) throw new Error("preset not found");

  let cookieStoreId;
  if (CAP.containers) {
    const c = await ensureContainer(preset.container, preset.color, preset.icon);
    cookieStoreId = c.cookieStoreId;
    if (preset.profileId) {
      S.containerBind[cookieStoreId] = preset.profileId;
      await save();
    }
  }

  const tab = await api.tabs.create({
    url: preset.url,
    active: true,
    ...(cookieStoreId ? { cookieStoreId } : {}),
  });
  if (!cookieStoreId && preset.profileId) {
    S.tabBind[tab.id] = preset.profileId;
    await saveSession();
  }
  return { tabId: tab.id, cookieStoreId: cookieStoreId || null };
}

/* Chrome degraded path: global proxy only. */
async function setGlobalProxy(profileId) {
  if (!CAP.globalProxy) throw new Error("no global proxy API");
  const p = profileById(profileId);
  if (!p || p.kind === "direct") {
    await api.proxy.settings.clear({ scope: "regular" });
    return { mode: "direct" };
  }
  const scheme = p.kind === "socks5" ? "socks5" : p.kind === "socks4" ? "socks4" : p.kind;
  await api.proxy.settings.set({
    scope: "regular",
    value: {
      mode: "fixed_servers",
      rules: { singleProxy: { scheme, host: p.host, port: Number(p.port) }, bypassList: ["localhost", "127.0.0.1"] },
    },
  });
  return { mode: "global", profile: p.name };
}

// ------------------------------------------------------------------ messages
const handlers = {
  async getState() {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    let identities = [];
    if (CAP.containers) {
      try { identities = await api.contextualIdentities.query({}); } catch (_) {}
    }
    const csid = tab ? (tab.cookieStoreId || tabStore.get(tab.id)) : null;
    return {
      cap: CAP,
      profiles: S.profiles,
      presets: S.presets,
      containerBind: S.containerBind,
      settings: S.settings,
      identities,
      tab: tab ? {
        id: tab.id,
        title: tab.title,
        url: tab.url,
        cookieStoreId: csid,
        boundProfile: S.tabBind[tab.id] ||
                      (csid ? S.containerBind[csid] : null) || null,
        boundVia: S.tabBind[tab.id] ? "tab" : (csid && S.containerBind[csid] ? "container" : null),
      } : null,
    };
  },

  async bindTab({ tabId, profileId }) {
    if (profileId) S.tabBind[tabId] = profileId; else delete S.tabBind[tabId];
    await saveSession();
    return { ok: true };
  },

  async bindContainer({ cookieStoreId, profileId }) {
    if (profileId) S.containerBind[cookieStoreId] = profileId;
    else delete S.containerBind[cookieStoreId];
    await save();
    return { ok: true };
  },

  async saveProfile({ profile }) {
    const i = S.profiles.findIndex(p => p.id === profile.id);
    if (i >= 0) S.profiles[i] = profile; else S.profiles.push(profile);
    await save();
    return { ok: true, profiles: S.profiles };
  },

  async deleteProfile({ id }) {
    S.profiles = S.profiles.filter(p => p.id !== id);
    for (const k of Object.keys(S.containerBind)) {
      if (S.containerBind[k] === id) delete S.containerBind[k];
    }
    for (const k of Object.keys(S.tabBind)) {
      if (S.tabBind[k] === id) delete S.tabBind[k];
    }
    await save(); await saveSession();
    return { ok: true, profiles: S.profiles };
  },

  async savePreset({ preset }) {
    const i = S.presets.findIndex(p => p.id === preset.id);
    if (i >= 0) S.presets[i] = preset; else S.presets.push(preset);
    await save();
    return { ok: true, presets: S.presets };
  },

  async deletePreset({ id }) {
    S.presets = S.presets.filter(p => p.id !== id);
    await save();
    return { ok: true, presets: S.presets };
  },

  async saveSettings({ settings }) {
    S.settings = Object.assign(S.settings, settings);
    await save();
    return { ok: true };
  },

  testProfile: ({ profileId }) => testProfile(profileId),
  launchPreset: ({ presetId }) => launchPreset(presetId),
  setGlobalProxy: ({ profileId }) => setGlobalProxy(profileId),

  async currentIp({ tabId }) {
    // measured from inside the tab, so it reflects that tab's actual route
    const out = await api.scripting.executeScript({
      target: { tabId },
      args: [S.settings.ipCheckUrl],
      func: async (url) => {
        try {
          const r = await fetch(url, { cache: "no-store" });
          return await r.text();
        } catch (e) { return "ERR " + e.message; }
      },
    });
    const text = (out && out[0] && out[0].result) || "";
    let ip = null;
    try { ip = JSON.parse(text).ip; } catch (_) {}
    return { text, ip };
  },

  async clearContainerCookies({ cookieStoreId }) {
    const all = await api.cookies.getAll({ storeId: cookieStoreId });
    let n = 0;
    for (const c of all) {
      const url = `http${c.secure ? "s" : ""}://${c.domain.replace(/^\./, "")}${c.path}`;
      try { await api.cookies.remove({ url, name: c.name, storeId: cookieStoreId }); n++; } catch (_) {}
    }
    return { removed: n };
  },
};

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const fn = handlers[msg && msg.type];
  if (!fn) return false;
  Promise.resolve(fn(msg))
    .then(r => sendResponse({ ok: true, data: r }))
    .catch(e => sendResponse({ ok: false, error: String(e && e.message || e) }));
  return true;   // async
});

// ------------------------------------------------------------------- startup
(async () => { await load(); await primeTabs(); })();
