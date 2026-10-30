// Runs extension/firefox/background.js against a stand-in `browser` and prints what it did, as JSON.
const fs = require("fs"), vm = require("vm");
const mode = process.argv[2];                       // "ok" | "down" | "refused"
const calls = { native: [], badge: [], title: [] }, listeners = {};
let timer = null;
const browser = {
  browserAction: { setBadgeText: (o) => calls.badge.push(o.text), setBadgeBackgroundColor: () => {}, setTitle: (o) => calls.title.push(o.title) },
  runtime: { sendNativeMessage: async (host, msg) => {
    calls.native.push({ host, msg });
    if (mode === "down") throw new Error("No such native application org.tol.observer");
    if (mode === "refused") return { error: "TOL is not running" };
    return { recorded: 2, rejected: 1, reason: "host and page must be bare host names" };
  } },
  webRequest: {
    onSendHeaders: { addListener: (fn) => { listeners.send = fn; } },
    onResponseStarted: { addListener: (fn) => { listeners.resp = fn; } },
  },
};
const ctx = { browser, console, URL, setInterval: (fn) => { timer = fn; return 1; }, Date, String, Math, Map };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync("extension/firefox/background.js", "utf8"), ctx);
(async () => {
  await new Promise((r) => setTimeout(r, 20));
  const req = (url, top, hdrs, t) => listeners.send({ url, type: "xmlhttprequest", documentUrl: top, requestHeaders: hdrs, timeStamp: t });
  listeners.resp({ url: "https://ads.example/x", ip: "104.18.0.9" });
  req("https://ads.example/x?secret=1", "https://news.example/a", [{ name: "Sec-GPC", value: "1" }, { name: "Cookie", value: "z" }], 1800000000500);
  req("https://cdn.example/y", "https://news.example/a", [], 1800000000900);
  req("http://127.0.0.1:8731/api", "http://127.0.0.1:8731/", [], 1800000001000);
  await timer();
  await new Promise((r) => setTimeout(r, 20));
  console.log(JSON.stringify(calls));
})();
