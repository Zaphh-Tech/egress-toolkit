"use strict";
const api = globalThis.browser ?? globalThis.chrome;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));

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

let ST = null, editing = null;
const uid = () => Math.random().toString(36).slice(2, 10);

const parseHeaders = txt => txt.split("\n").map(l => l.trim()).filter(Boolean).map(l => {
  const i = l.indexOf(":");
  return i < 0 ? null : { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim() };
}).filter(Boolean);

const fmtHeaders = hs => (hs || []).map(h => `${h.name}: ${h.value}`).join("\n");

function label(p) {
  if (!p) return "direct";
  return p.kind === "direct" ? "direct" : `${p.kind}://${p.host}:${p.port}`;
}

async function render() {
  ST = await send("getState");
  const { cap, profiles, presets, identities, containerBind, settings } = ST;

  $("#capbanner").innerHTML = cap.perRequest
    ? ""
    : `<div class="banner"><b>Chrome detected.</b> Chrome's extension APIs have no per-tab proxy
       and no container cookie jars, so this build falls back to a single global proxy and no
       isolation. Run it in Firefox to get what you actually asked for.</div>`;

  // profiles table
  $("#ptable").innerHTML = profiles.map(p => `<tr>
      <td>${esc(p.name)}</td>
      <td class="mono">${esc(label(p))}${p.username ? " <span class='hint'>(auth)</span>" : ""}</td>
      <td class="mono hint">${esc((p.headers || []).map(h => h.name).join(", ")) || "—"}</td>
      <td class="hint">${esc(p.note || "")}</td>
      <td><button class="mini" data-edit="${p.id}">edit</button>
          <button class="mini bad" data-del="${p.id}">del</button></td>
    </tr>`).join("") || `<tr><td colspan="5" class="hint">none</td></tr>`;

  const opts = ['<option value="">— direct —</option>']
    .concat(profiles.map(p => `<option value="${p.id}">${esc(p.name)}</option>`)).join("");

  // containers
  $("#ctable").innerHTML = cap.containers
    ? (identities.map(i => `<tr>
        <td>${esc(i.name)}</td>
        <td><select data-cbind="${i.cookieStoreId}">${opts}</select></td>
        <td class="hint mono">${esc(i.cookieStoreId)}</td>
      </tr>`).join("") || `<tr><td colspan="3" class="hint">no containers yet</td></tr>`)
    : `<tr><td colspan="3" class="hint">containers unavailable in this browser</td></tr>`;
  for (const sel of document.querySelectorAll("[data-cbind]")) {
    sel.value = containerBind[sel.dataset.cbind] || "";
  }

  $("#s-profile").innerHTML = opts;

  $("#stable").innerHTML = presets.map(p => `<tr>
      <td>${esc(p.name)}</td><td>${esc(p.container)}</td>
      <td>${esc(label(profiles.find(x => x.id === p.profileId)))}</td>
      <td class="mono hint">${esc(p.url)}</td>
      <td><button class="mini bad" data-delpreset="${p.id}">del</button></td>
    </tr>`).join("") || `<tr><td colspan="5" class="hint">none</td></tr>`;

  $("#ipurl").value = settings.ipCheckUrl;
}

function clearForm() {
  editing = null;
  for (const id of ["f-name","f-host","f-port","f-user","f-pass","f-headers","f-note"]) $("#" + id).value = "";
  $("#f-kind").value = "socks5"; $("#f-dns").checked = true; $("#f-editing").textContent = "";
}

document.addEventListener("click", async e => {
  const t = e.target;

  if (t.id === "f-save") {
    const profile = {
      id: editing || uid(),
      name: $("#f-name").value.trim() || "unnamed",
      kind: $("#f-kind").value,
      host: $("#f-host").value.trim(),
      port: Number($("#f-port").value) || 0,
      username: $("#f-user").value.trim(),
      password: $("#f-pass").value,
      proxyDNS: $("#f-dns").checked,
      headers: parseHeaders($("#f-headers").value),
      note: $("#f-note").value.trim(),
    };
    await send("saveProfile", { profile });
    clearForm(); await render();
  }

  if (t.id === "f-reset") clearForm();

  if (t.dataset.edit) {
    const p = ST.profiles.find(x => x.id === t.dataset.edit);
    editing = p.id;
    $("#f-name").value = p.name; $("#f-kind").value = p.kind;
    $("#f-host").value = p.host || ""; $("#f-port").value = p.port || "";
    $("#f-user").value = p.username || ""; $("#f-pass").value = p.password || "";
    $("#f-dns").checked = p.proxyDNS !== false;
    $("#f-headers").value = fmtHeaders(p.headers);
    $("#f-note").value = p.note || "";
    $("#f-editing").textContent = `editing "${p.name}"`;
    scrollTo(0, 0);
  }

  if (t.dataset.del) { await send("deleteProfile", { id: t.dataset.del }); await render(); }
  if (t.dataset.delpreset) { await send("deletePreset", { id: t.dataset.delpreset }); await render(); }

  if (t.id === "c-add") {
    const name = $("#c-new").value.trim();
    if (!name) return;
    await api.contextualIdentities.create({ name, color: "purple", icon: "briefcase" });
    $("#c-new").value = ""; await render();
  }

  if (t.id === "s-save") {
    const preset = {
      id: uid(),
      name: $("#s-name").value.trim() || "unnamed",
      container: $("#s-container").value.trim() || "hunt",
      url: $("#s-url").value.trim(),
      profileId: $("#s-profile").value || null,
      color: "purple", icon: "briefcase",
    };
    await send("savePreset", { preset });
    $("#s-name").value = $("#s-container").value = $("#s-url").value = "";
    await render();
  }

  if (t.id === "saveset") {
    await send("saveSettings", { settings: { ipCheckUrl: $("#ipurl").value.trim() } });
    t.textContent = "saved"; setTimeout(() => t.textContent = "Save", 1200);
  }

  if (t.id === "export") {
    const blob = new Blob([JSON.stringify({
      profiles: ST.profiles, presets: ST.presets,
      containerBind: ST.containerBind, settings: ST.settings,
    }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `hunt-containers-${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(a.href);
  }

  if (t.id === "import") $("#file").click();
});

$("#file").addEventListener("change", async e => {
  const f = e.target.files[0]; if (!f) return;
  const d = JSON.parse(await f.text());
  for (const p of d.profiles || []) await send("saveProfile", { profile: p });
  for (const p of d.presets || []) await send("savePreset", { preset: p });
  if (d.settings) await send("saveSettings", { settings: d.settings });
  e.target.value = ""; await render();
});

document.addEventListener("change", async e => {
  if (e.target.dataset.cbind) {
    await send("bindContainer", {
      cookieStoreId: e.target.dataset.cbind,
      profileId: e.target.value || null,
    });
  }
});

render();
