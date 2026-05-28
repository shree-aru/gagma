import sys
sys.stdout.reconfigure(encoding='utf-8')
import httpx, time

PORT = 8001

# Upload APK
print("Uploading InsecureBankv2.apk...")
files = {'file': ('InsecureBankv2.apk', open(r'c:\Users\HP\Downloads\apps\InsecureBankv2.apk', 'rb'), 'application/vnd.android.package-archive')}
r = httpx.post(f'http://localhost:{PORT}/api/analyze', files=files, timeout=30)
data = r.json()
aid = data['analysis_id']
print(f"Analysis ID: {aid}, Status: {data['status']}")

# Poll for completion
start = time.time()
for i in range(60):
    time.sleep(3)
    r = httpx.get(f'http://localhost:{PORT}/api/status/{aid}', timeout=10)
    d = r.json()
    status = d['status']
    elapsed = time.time() - start
    print(f'[{elapsed:.1f}s] Status: {status}')
    if status in ('COMPLETE', 'FAILED'):
        break

elapsed = time.time() - start
print(f'\n{"="*60}')
print(f'FINAL STATUS: {d["status"]} (took {elapsed:.1f}s)')
print(f'{"="*60}')

if d.get('risk_score'):
    rs = d['risk_score']
    print(f'\nRisk Score: {rs["total_score"]}/100 ({rs["risk_level"]})')

if d.get('behavioral_findings'):
    print(f'\nBehavioral Findings ({len(d["behavioral_findings"])}):')
    for f in d['behavioral_findings'][:5]:
        print(f'  [{f["severity"].upper():8s}] {f["pattern_name"]}')

if d.get('static_analysis'):
    sa = d['static_analysis']
    print(f'\nStatic Analysis:')
    print(f'  Package:     {sa["metadata"]["package_name"]}')
    print(f'  Permissions: {len(sa["permissions"])} ({sum(1 for p in sa["permissions"] if p["is_suspicious"])} dangerous)')
    print(f'  APIs found:  {len(sa["suspicious_api_calls"])}')
    print(f'  URLs:        {len(sa["extracted_urls"])}')

if d.get('error'):
    print(f'\nERROR: {d["error"]}')
