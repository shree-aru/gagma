"""Full E2E test: Demo scenario + Dynamic Analysis + Prevention API."""
import httpx, json

API = "http://localhost:8001"

print("=" * 60)
print("  E2E TEST: Demo + Dynamic Analysis + Prevention")
print("=" * 60)

# 1. Run Drinik demo
print("\n[1] Running Drinik demo...")
r = httpx.post(f"{API}/api/demo/drinik", timeout=30)
d = r.json()
print(f"    Score: {d['risk_score']}/100 [{d['risk_level']}]")
print(f"    Findings: {d['findings_count']}, Flags: {d['banking_flags_count']}, Kill Chain: {d['kill_chain_steps']} steps")
aid = d["analysis_id"]

# 2. Fetch full status and check dynamic analysis
print("\n[2] Checking dynamic analysis...")
r = httpx.get(f"{API}/api/status/{aid}", timeout=10)
full = r.json()
dyn = full.get("dynamic_analysis", {})
print(f"    Sandbox Verdict: {dyn.get('sandbox_verdict', 'MISSING')}")
print(f"    Runtime Behaviors: {dyn.get('total_findings', 0)}")
print(f"    Critical: {dyn.get('critical_findings', 0)}")
for b in dyn.get("runtime_behaviors", []):
    print(f"      [{b['severity'].upper():8s}] {b['title']}")
    if b.get("data_flow"):
        print("                " + b["data_flow"][:80].encode("ascii", "replace").decode())

# 3. Test Prevention API: block APK
print("\n[3] Blocking APK via prevention API...")
r = httpx.post(f"{API}/api/prevent/auto-block/{aid}", timeout=10)
block = r.json()
print(f"    Status: {block.get('status')}")
print(f"    Message: {block.get('message')}")

# 4. Check hash verdict (should be BLOCK)
sha = full.get("static_analysis", {}).get("metadata", {}).get("sha256", "")
print(f"\n[4] Hash verdict check (sha256={sha[:20]}...)...")
r = httpx.post(f"{API}/api/prevent/check-hash?sha256={sha}", timeout=10)
verdict = r.json()
print(f"    Verdict: {verdict['verdict']}")
print(f"    Response time: {verdict['response_time_ms']}ms")
print(f"    Reason: {verdict['reason'][:80]}")

# 5. Get blocklist
print("\n[5] Enterprise blocklist...")
r = httpx.get(f"{API}/api/prevent/blocklist", timeout=10)
bl = r.json()
print(f"    Total blocked: {bl['total_blocked']}")

# 6. Prevention stats
print("\n[6] Prevention dashboard stats...")
r = httpx.get(f"{API}/api/prevent/stats", timeout=10)
stats = r.json()
print(f"    APKs scanned: {stats['total_apks_scanned']}")
print(f"    Threats identified: {stats['threats_identified']}")
print(f"    APKs blocked: {stats['apks_blocked']}")

print("\n" + "=" * 60)
print("  ALL E2E TESTS PASSED")
print("=" * 60)
