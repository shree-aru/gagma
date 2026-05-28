import httpx, time, sys

sys.path.insert(0, 'backend')
base = 'http://localhost:8001'
checks = []

# 1. Frontend
try:
    r = httpx.get(f'{base}/', timeout=5)
    checks.append(('Frontend (/)', 'OK' if r.status_code == 200 else f'ERROR {r.status_code}'))
except Exception as e:
    checks.append(('Frontend (/)', 'FAIL: ' + str(e)))

# 2. Debug config - API Keys
try:
    r = httpx.get(f'{base}/debug-config', timeout=5)
    d = r.json()
    gemini_ok = 'AIza' in d.get('GEMINI_API_KEY_config', '')
    vt_ok = d.get('VIRUSTOTAL_API_KEY', '')[:5] == 'd534b'
    checks.append(('Gemini API Key', 'OK - loaded' if gemini_ok else 'MISSING'))
    checks.append(('VT API Key', 'OK - loaded' if vt_ok else 'MISSING'))
    checks.append(('LLM Provider', 'OK - ' + d.get('LLM_PROVIDER', '?')))
except Exception as e:
    checks.append(('Config', 'FAIL: ' + str(e)))

# 3. Analyses list
try:
    r = httpx.get(f'{base}/api/analyses', timeout=5)
    analyses = r.json()
    completed = [a for a in analyses if a.get('status') == 'COMPLETE']
    checks.append(('Analyses API', f'OK - {len(analyses)} total, {len(completed)} completed'))
except Exception as e:
    checks.append(('Analyses API', 'FAIL: ' + str(e)))

# 4. Neo4j
try:
    from services.graph_service import driver
    with driver.session() as s:
        result = s.run("MATCH (n) RETURN count(n) as cnt").single()
        checks.append(('Neo4j Graph DB', f'OK - {result["cnt"]} nodes stored'))
except Exception as e:
    checks.append(('Neo4j Graph DB', 'FAIL: ' + str(e)[:80]))

# 5. LLM quick test
try:
    from services.llm_service import call_llm
    t = time.time()
    res = call_llm('You are a cybersecurity analyst.', 'Say OK in 3 words.', temperature=0)
    elapsed = time.time() - t
    checks.append(('Gemini LLM', f'OK - {elapsed:.1f}s response: {res[:50].strip()}'))
except Exception as e:
    checks.append(('Gemini LLM', 'FAIL: ' + str(e)[:100]))

# Summary
print('\n' + '='*60)
print('  GAGMA SYSTEM HEALTH CHECK')
print('='*60)
ok_count = 0
for name, status in checks:
    icon = 'OK' if status.startswith('OK') else 'XX'
    if status.startswith('OK'):
        ok_count += 1
    print(f'  [{icon}] {name}: {status}')
print('='*60)
print(f'  Result: {ok_count}/{len(checks)} checks passed')
print('='*60)
