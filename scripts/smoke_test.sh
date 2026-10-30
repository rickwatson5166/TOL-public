#!/usr/bin/env bash
# Launch a built TOL executable and check it end to end: dashboard, live API, auth, and Quit.
# usage: scripts/smoke_test.sh path/to/tol-or-TOL.app/Contents/MacOS/TOL
set -euo pipefail
bin="$1"; port="${2:-8765}"
home="$(mktemp -d)"
py=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then py="$cand"; break; fi
done
[[ -n "$py" ]] || { echo "FAIL: no working python found for the checks"; exit 1; }
mkdir -p "$home/h"
HOME="$home/h" USERPROFILE="$home/h" "$bin" --no-browser --port "$port" --data-dir "$home" > "$home/out.log" 2>&1 &
pid=$!
dump() { echo "----- app output -----"; cat "$home/out.log" || true; echo "----- exit: process alive? -----"; kill -0 "$pid" 2>/dev/null && echo yes || echo no; }
trap 'rc=$?; [[ $rc -ne 0 ]] && dump; kill $pid 2>/dev/null || true' EXIT
# wait up to 90s for the server to answer (first launch of a bundled app can be slow)
for _ in $(seq 1 180); do
  curl -s -m 2 -o /dev/null "http://127.0.0.1:$port/" && break
  kill -0 "$pid" 2>/dev/null || { echo "FAIL: app exited during startup"; exit 1; }
  sleep 0.5
done
[[ -s "$home/token" ]] || { echo "FAIL: app never wrote its token (did not start)"; exit 1; }
token="$(cat "$home/token")"
jar="$home/jar"
code() { curl -s -m 5 -o /dev/null -w "%{http_code}" "$@"; }

[[ "$(code "http://127.0.0.1:$port/api/state")" == "403" ]] || { echo "FAIL: API open without token"; exit 1; }
curl -s -m 5 -c "$jar" -o /dev/null "http://127.0.0.1:$port/?t=$token"
[[ "$(code -b "$jar" "http://127.0.0.1:$port/")" == "200" ]] || { echo "FAIL: dashboard not served"; cat "$home/out.log"; exit 1; }
# save the page, then search the file: piping into `grep -q` makes curl fail (SIGPIPE) once the page outgrows the pipe
curl -s -m 5 -b "$jar" -o "$home/page.html" "http://127.0.0.1:$port/"
grep -q "<title>TOL" "$home/page.html" || { echo "FAIL: wrong page"; exit 1; }
sleep 4
curl -s -m 5 -b "$jar" "http://127.0.0.1:$port/api/state" > "$home/state.json"
"$py" - "$home/state.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["collector_errors"] == 0, f"collector errors: {d['collector_errors']}"
assert d["uptime"] > 0 and isinstance(d["rows"], list) and d["notices"]
print(f"live state OK: {len(d['rows'])} destinations, {d['totals']['sent']} bytes sent, errors={d['collector_errors']}")
PY
# what a user does: record for a few seconds, build the evidence package, then check it with the verifier the package
# carries (no TOL involved). This proves the packaged app bundles everything the evidence feature needs.
post() { curl -s -m 30 -b "$jar" -H "X-TOL: 1" -X POST "$@" > /dev/null; }
post "http://127.0.0.1:$port/api/record/start"
sleep 4
post "http://127.0.0.1:$port/api/record/stop"
post "http://127.0.0.1:$port/api/evidence"
folder="$(ls -dt "$home"/evidence/*/ 2>/dev/null | head -1)"
[[ -n "$folder" && -f "${folder}verify.py" ]] || { echo "FAIL: no evidence package was created"; exit 1; }
[[ -f "${folder}tol_timestamp.py" ]] || { echo "FAIL: package is missing its timestamp reader"; exit 1; }
"$py" "${folder}verify.py" "${folder}" > "$home/verify.out" 2>&1 || { echo "FAIL: the package's own verifier failed"; cat "$home/verify.out"; exit 1; }
grep -q "ALL CHECKS PASSED" "$home/verify.out" || { echo "FAIL: verifier did not report success"; cat "$home/verify.out"; exit 1; }
echo "evidence package built and verified OK"
# the browser observer: set-up button, observations through the real helper into a recording, the site report, and the
# package's own verifier checking the observations
[[ "$(code -X POST -b "$jar" -H "X-TOL: 1" "http://127.0.0.1:$port/api/browser-helper/install")" == "200" ]] || { echo "FAIL: observer set-up refused"; exit 1; }
[[ -f "$home/extension/firefox/manifest.json" ]] || { echo "FAIL: the extension was not bundled in this build"; exit 1; }
post "http://127.0.0.1:$port/api/record/start"
"$py" - "$bin" "$home" <<'PY'
import json, struct, subprocess, sys, time
bin_, home = sys.argv[1], sys.argv[2]
now = int(time.time() * 1000)
batch = [{"host": "tracker.example", "page": "news.example", "ts_ms": now, "gpc": True, "count": 3},
         {"host": "cdn.example", "page": "news.example", "ts_ms": now, "gpc": False, "count": 1}]
data = json.dumps(batch).encode()
p = subprocess.run([bin_, "--native-host", "--data-dir", home], input=struct.pack("<I", len(data)) + data, capture_output=True, timeout=60)
n = struct.unpack("<I", p.stdout[:4])[0]
reply = json.loads(p.stdout[4:4 + n])
assert reply.get("recorded") == 2 and reply.get("rejected") == 0, f"the packaged helper did not deliver the observations: {reply} {p.stderr[:300]!r}"
print("packaged helper delivered observations OK")
PY
post "http://127.0.0.1:$port/api/record/stop"
curl -s -m 5 -b "$jar" "http://127.0.0.1:$port/api/site-report?page=news.example" > "$home/site.json"
"$py" - "$home/site.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert {d["host"] for d in r["destinations"]} == {"tracker.example", "cdn.example"}, r
assert "does not say" in r["text"]
print("site report OK")
PY
post "http://127.0.0.1:$port/api/evidence"
folder="$(ls -dt "$home"/evidence/*/ 2>/dev/null | head -1)"
"$py" "${folder}verify.py" "${folder}" > "$home/verify2.out" 2>&1 || { echo "FAIL: verifier failed on a package with observations"; cat "$home/verify2.out"; exit 1; }
grep -q "PASS  Browser-signal observations" "$home/verify2.out" || { echo "FAIL: verifier did not check the observations"; cat "$home/verify2.out"; exit 1; }
echo "browser observer OK"
[[ "$(code -X POST -b "$jar" "http://127.0.0.1:$port/api/quit")" == "403" ]] || { echo "FAIL: quit works without header"; exit 1; }
[[ "$(code -X POST -b "$jar" -H "X-TOL: 1" "http://127.0.0.1:$port/api/quit")" == "200" ]] || { echo "FAIL: quit refused"; exit 1; }
for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || { echo "SMOKE TEST PASSED"; exit 0; }; sleep 0.5; done
echo "FAIL: app did not exit after Quit"; exit 1
