import sys
sys.stdout.reconfigure(encoding='utf-8')
import httpx, json, time

# Upload APK
print("Uploading InsecureBankv2.apk...")
files = {'file': ('InsecureBankv2.apk', open(r'c:\Users\HP\Downloads\apps\InsecureBankv2.apk', 'rb'), 'application/vnd.android.package-archive')}
r = httpx.post('http://localhost:8000/api/analyze', files=files, timeout=30)
data = r.json()
aid = data['analysis_id']
print(f"Analysis ID: {aid}, Status: {data['status']}")

# Poll for completion
for i in range(60):  # up to 3 minutes
    time.sleep(3)
    r = httpx.get(f'http://localhost:8000/api/status/{aid}', timeout=10)
    d = r.json()
    status = d['status']
    print(f'[{i*3}s] Status: {status}')
    if status in ('COMPLETE', 'FAILED'):
        break

print(f'\n{"="*60}')
print(f'FINAL STATUS: {d["status"]}')
print(f'{"="*60}')

if d.get('risk_score'):
    rs = d['risk_score']
    print(f'\nRisk Score: {rs["total_score"]}/100 ({rs["risk_level"]})')
    print(f'  Permissions: {rs["permissions_score"]}/25')
    print(f'  API Calls:   {rs["api_calls_score"]}/25')
    print(f'  Behavioral:  {rs["behavioral_score"]}/30')
    print(f'  Threat Intel: {rs["threat_intel_score"]}/20')

if d.get('behavioral_findings'):
    print(f'\nBehavioral Findings ({len(d["behavioral_findings"])}):')
    for f in d['behavioral_findings'][:10]:
        print(f'  [{f["severity"].upper():8s}] {f["pattern_name"]}')

if d.get('graph_data'):
    g = d['graph_data']
    print(f'\nGraph: {len(g.get("nodes",[]))} nodes, {len(g.get("edges",[]))} edges')

if d.get('static_analysis'):
    sa = d['static_analysis']
    print(f'\nStatic Analysis:')
    print(f'  Package:     {sa["metadata"]["package_name"]}')
    print(f'  Version:     {sa["metadata"]["version_name"]}')
    print(f'  Min SDK:     {sa["metadata"]["min_sdk"]}')
    print(f'  Target SDK:  {sa["metadata"]["target_sdk"]}')
    print(f'  Permissions: {len(sa["permissions"])} ({sum(1 for p in sa["permissions"] if p["is_suspicious"])} dangerous)')
    print(f'  Activities:  {len(sa.get("activities",[]))}')
    print(f'  Services:    {len(sa.get("services",[]))}')
    print(f'  Receivers:   {len(sa.get("receivers",[]))}')
    print(f'  APIs found:  {len(sa["suspicious_api_calls"])}')
    print(f'  URLs:        {len(sa["extracted_urls"])}')
    print(f'  IPs:         {len(sa["extracted_ips"])}')
    print(f'  Call edges:  {sa.get("call_graph_edges",0)}')
    print(f'  Classes:     {sa.get("classes_count",0)}')
    print(f'  Methods:     {sa.get("methods_count",0)}')
    
    if sa["suspicious_api_calls"]:
        print(f'\n  Top Suspicious API Calls:')
        for api in sa["suspicious_api_calls"][:15]:
            print(f'    [{api["severity"]:8s}] {api["category"]:15s} | {api["api_call"][:80]}')

    if sa["extracted_urls"]:
        print(f'\n  URLs found:')
        for url in sa["extracted_urls"][:10]:
            print(f'    {url}')

    if sa["extracted_ips"]:
        print(f'\n  IPs found:')
        for ip in sa["extracted_ips"][:10]:
            print(f'    {ip}')

if d.get('error'):
    print(f'\nERROR: {d["error"]}')
