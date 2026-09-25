"use strict";
const api = globalThis.browser ?? globalThis.chrome;
const $ = s => document.querySelector(s);

// Firefox's browser.* is promise-based and takes no callback; Chrome's chrome.*
// is callback-based. Same call, two different contracts - handle both.
function send(type, extra = {}) {
  const msg = { type, ...extra };
  const unwrap = r => {
    if (!r) throw new Error("no response from background");
    if (!r.ok) throw new Error(r.error);
    return r.data;
  };
  if (globalThis.browser && globalThis.browser.runtime) {
    return globalThis.browser.runtime.sendMessage(msg).then(unwrap);
  }
  return new Promise((res, rej) =>
    globalThis.chrome.runtime.sendMessage(msg, r => {
      try { res(unwrap(r)); } catch (e) { rej(e); }
    }));
}

let ST = null;

function proxyLabel(p) {
  if (!p) return "direct";
  if (p.kind === "direct") return "direct";
  return `${p.kind}://${p.host}:${p.port}`;
}

async function render() {
  ST = await send("getState");
  const { cap, profiles, presets, tab, identities, containerBind } = ST;

  $("#cap").textContent = cap.perRequest ? "per-tab" : "global only";
  $("#cap").className = "pill " + (cap.perRequest ? "good" : "warn");

  if (!tab) return;
  $("#tabtitle").textContent = tab.title || tab.url || "—";

  const ident = identities.find(i => i.cookieStoreId === tab.cookieStoreId);
  $("#container").textContent = ident ? ident.name : "default (shared cookies)";

  // proxy select
  const sel = $("#tabproxy");
  sel.innerHTML = "";
  const none = document.createElement("option");
  none.value = ""; none.textContent = "— direct (no proxy) —";
  sel.appendChild(none);
  for (const p of profiles) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = `${p.name}  ·  ${proxyLabel(p)}`;
    sel.appendChild(o);
  }
  sel.value = tab.boundProfile || "";
  $("#via").textContent = tab.boundVia === "container"
    ? `inherited from container "${ident ? ident.name : "?"}" — changing here overrides just this tab`
    : tab.boundVia === "tab" ? "set on this tab only (resets when the tab closes)"
    : "";

  // proxy list
  const pl = $("#plist");
  pl.innerHTML = "";
  if (!profiles.length) pl.innerHTML = '<div class="empty">No proxies yet — add them in Settings.</div>';
  for (const p of profiles) {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `<span class="nm">${esc(p.name)}</span>
                     <span class="st" data-st="${p.id}"></span>
                     <button class="mini" data-test="${p.id}">test</button>`;
    pl.appendChild(row);
  }

  // presets
  const pr = $("#presets");
  pr.innerHTML = "";
  if (!presets.length) pr.innerHTML = '<div class="empty">No presets yet — add them in Settings.</div>';
  for (const p of presets) {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `<span class="nm">${esc(p.name)}</span>
                     <button class="mini acc" data-launch="${p.id}">launch</button>`;
    pr.appendChild(row);
  }
}

const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));

document.addEventListener("click", async e => {
  const t = e.target;

  if (t.dataset.test) {
    const cell = document.querySelector(`[data-st="${t.dataset.test}"]`);
    cell.textContent = "…"; cell.className = "st";
    try {
      const r = await send("testProfile", { profileId: t.dataset.test });
      cell.textContent = r.ok ? `${r.ip || "?"} ${r.ms}ms` : "unreachable";
      cell.className = "st " + (r.ok ? "ok" : "bad");
    } catch (err) { cell.textContent = "error"; cell.className = "st bad"; }
  }

  if (t.dataset.launch) {
    await send("launchPreset", { presetId: t.dataset.launch });
    window.close();
  }

  if (t.id === "ipbtn") {
    $("#ip").textContent = "…";
    try {
      const r = await send("currentIp", { tabId: ST.tab.id });
      $("#ip").textContent = r.ip || r.text.slice(0, 40) || "?";
    } catch (err) { $("#ip").textContent = "n/a (restricted page)"; }
  }

  if (t.id === "clearcookies") {
    if (!ST.tab.cookieStoreId) return;
    const r = await send("clearContainerCookies", { cookieStoreId: ST.tab.cookieStoreId });
    t.textContent = `cleared ${r.removed}`;
    setTimeout(() => { t.textContent = "clear container cookies"; }, 1800);
  }

  if (t.id === "opts") api.runtime.openOptionsPage();
});

$("#tabproxy").addEventListener("change", async e => {
  const pid = e.target.value || null;
  if (ST.cap.perRequest) {
    await send("bindTab", { tabId: ST.tab.id, profileId: pid });
  } else {
    await send("setGlobalProxy", { profileId: pid });
  }
  await render();
});

render();
