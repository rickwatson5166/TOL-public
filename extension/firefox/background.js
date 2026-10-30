// TOL observer. Watches only; never blocks, edits or injects. For each outgoing request it keeps the destination host,
// the host of the page that caused it, a time, the server address Firefox connected to, and whether the Sec-GPC: 1 header
// was present. No paths, queries, cookies or bodies are read or kept. Counts are batched per (host, page, signal, second)
// and handed to TOL's native helper, which passes them to TOL on this machine. Nothing is sent over the network.
//
// The toolbar button shows its own state, so a problem is visible without any developer tools: a green number is how many
// requests it has seen and a red "!" means TOL or its helper did not answer (hover the button for the reason).
"use strict";
const HOST = "org.tol.observer";
const pending = new Map();
const ipByHost = new Map();                 // the server address Firefox connected to, per host (so TOL can use its own labels)
const LOCAL = /^(localhost|127\.|\[?::1\]?$)/;
const state = { seen: 0, answered: 0, kept: 0, rejected: 0, lastReject: "", lastError: "" };
let lastContact = 0;

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return null; }
}

function paint() {
  const bad = state.lastError !== "";
  browser.browserAction.setBadgeText({ text: bad ? "!" : String(Math.min(state.seen, 9999)) });
  browser.browserAction.setBadgeBackgroundColor({ color: bad ? "#B3261E" : "#1B6B43" });
  browser.browserAction.setTitle({ title: "TOL observer: " + state.seen + " requests seen, TOL answered " + state.answered +
    " times, kept " + state.kept + " (TOL keeps data only while recording), turned away " + state.rejected +
    (state.lastReject ? " (" + state.lastReject + ")" : "") + (bad ? ". Problem: " + state.lastError : ".") });
}

async function send(batch) {
  lastContact = Date.now();
  try {
    const reply = await browser.runtime.sendNativeMessage(HOST, batch);     // TOL answers {"recorded": n} or {"error": ...}
    if (reply && reply.error) { state.lastError = String(reply.error); return false; }
    state.answered += 1;
    state.lastError = "";
    if (reply) {
      state.kept += Number(reply.recorded) || 0;
      state.rejected += Number(reply.rejected) || 0;
      if (reply.reason) state.lastReject = String(reply.reason).slice(0, 80);
    }
    return true;
  } catch (e) {
    state.lastError = "helper not reachable: " + String((e && e.message) || e);       // the batch is dropped; nothing is stored here
    return false;
  } finally {
    paint();
  }
}

browser.webRequest.onSendHeaders.addListener(
  (d) => {
    const host = hostOf(d.url);
    // credit the request to the top-level page the person is on, not to an ad or widget frame inside it
    const top = d.type === "main_frame" ? d.url
      : (d.frameAncestors && d.frameAncestors.length ? d.frameAncestors[d.frameAncestors.length - 1].url : (d.documentUrl || d.originUrl || d.url));
    const page = hostOf(top);
    if (!host || !page || !/^https?:/.test(d.url)) return;
    if (LOCAL.test(host) || LOCAL.test(page)) return;      // never watch this computer's own pages, TOL's dashboard included
    const gpc = (d.requestHeaders || []).some((h) => h.name.toLowerCase() === "sec-gpc" && h.value === "1");
    const sec = Math.floor(d.timeStamp / 1000) * 1000;
    const key = host + "|" + page + "|" + gpc + "|" + sec;
    const cur = pending.get(key);
    if (cur) cur.count += 1; else pending.set(key, { host, page, ts_ms: sec, gpc, count: 1 });
    state.seen += 1;
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

browser.webRequest.onResponseStarted.addListener(
  (d) => { const h = hostOf(d.url); if (h && d.ip) ipByHost.set(h, d.ip); },
  { urls: ["<all_urls>"] }
);

async function flush() {
  if (!pending.size) {
    if (Date.now() - lastContact > 30000) await send([]);      // an empty hello: keeps the status honest while idle
    else paint();
    return;
  }
  const items = [...pending.values()].slice(0, 500);
  for (const b of items) pending.delete(b.host + "|" + b.page + "|" + b.gpc + "|" + b.ts_ms);
  await send(items.map((b) => (ipByHost.has(b.host) ? { ...b, ip: ipByHost.get(b.host) } : b)));
}

paint();
send([]);                                    // say hello to TOL's helper as soon as the extension loads
setInterval(flush, 5000);
