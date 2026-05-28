import httpx, json
r = httpx.get('http://localhost:8001/api/status/ee38f533', timeout=10)
d = r.json()

print("=== BANKING FLAGS ===")
for f in d.get('banking_flags', []):
    print("  [" + f["severity"].upper() + "] " + f["flag_type"] + ": " + f["title"])

print("\n=== KILL CHAIN ===")
for s in d.get('kill_chain', []):
    print("  Stage " + str(s["stage"]) + ": " + s["name"] + " (" + s["technique"] + ")")

print("\n=== MITRE TAGS (first 3 findings) ===")
for f in d.get('behavioral_findings', [])[:3]:
    print("  " + f["pattern_name"] + ":")
    for t in f.get('mitre_techniques', []):
        print("    - " + t)

print("\n=== THREAT INTEL ===")
ti = d.get('threat_intel') or {}
vt = ti.get('virustotal', {})
print("  VT found:", vt.get('found'))
print("  Detection rate:", vt.get('detection_rate'))
