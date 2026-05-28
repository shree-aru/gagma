"""
GAGMA Graph Service — Neo4j integration for the Malware Knowledge Graph
Handles connection, schema creation, data ingestion, and querying.
"""
from __future__ import annotations

import logging
from typing import Optional
from contextlib import contextmanager

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE
from models.schemas import StaticAnalysisResult

logger = logging.getLogger(__name__)

# ── Global driver ──────────────────────────────────────
_driver: Optional[Driver] = None
_connected: bool = False


def get_driver() -> Optional[Driver]:
    """Get or create the Neo4j driver."""
    global _driver, _connected
    if _driver is not None and _connected:
        return _driver
    try:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        _driver.verify_connectivity()
        _connected = True
        logger.info(f"Connected to Neo4j at {NEO4J_URI}")
        return _driver
    except (ServiceUnavailable, AuthError, Exception) as e:
        logger.warning(f"Neo4j connection failed: {e}. Running in offline mode.")
        _connected = False
        return None


def close_driver():
    """Close the Neo4j driver."""
    global _driver, _connected
    if _driver:
        _driver.close()
        _driver = None
        _connected = False


def is_connected() -> bool:
    """Check if Neo4j is available."""
    return _connected and _driver is not None


@contextmanager
def get_session():
    """Context manager for Neo4j sessions."""
    driver = get_driver()
    if driver is None:
        yield None
        return
    session = driver.session(database=NEO4J_DATABASE)
    try:
        yield session
    finally:
        session.close()


# ── Schema Setup ───────────────────────────────────────

def setup_schema():
    """Create constraints and indexes for the graph schema."""
    with get_session() as session:
        if session is None:
            logger.warning("Skipping schema setup — Neo4j not connected")
            return

        constraints = [
            "CREATE CONSTRAINT apk_hash IF NOT EXISTS FOR (a:APK) REQUIRE a.sha256 IS UNIQUE",
            "CREATE CONSTRAINT perm_name IF NOT EXISTS FOR (p:Permission) REQUIRE p.name IS UNIQUE",
            "CREATE CONSTRAINT api_name IF NOT EXISTS FOR (api:APICall) REQUIRE api.name IS UNIQUE",
            "CREATE CONSTRAINT class_name IF NOT EXISTS FOR (c:Class) REQUIRE c.name IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX apk_package IF NOT EXISTS FOR (a:APK) ON (a.package_name)",
            "CREATE INDEX method_name IF NOT EXISTS FOR (m:Method) ON (m.name)",
            "CREATE INDEX url_value IF NOT EXISTS FOR (u:URL) ON (u.value)",
            "CREATE INDEX ip_value IF NOT EXISTS FOR (ip:IPAddress) ON (ip.value)",
        ]

        for query in constraints + indexes:
            try:
                session.run(query)
            except Exception as e:
                logger.debug(f"Schema query note: {e}")

        logger.info("Neo4j schema setup complete")


# ── Data Ingestion ─────────────────────────────────────

def ingest_analysis(analysis_id: str, result: StaticAnalysisResult) -> dict:
    """
    Ingest all static analysis results into Neo4j as a knowledge graph.
    Returns graph data formatted for vis.js visualization.
    """
    vis_nodes = []
    vis_edges = []
    node_id_counter = 0

    with get_session() as session:
        if session is None:
            logger.warning("Neo4j not connected — generating offline graph data")
            return _generate_offline_graph(analysis_id, result)

        meta = result.metadata

        # ── Create APK node ────────────────────────────
        session.run("""
            MERGE (a:APK {sha256: $sha256})
            SET a.package_name = $package_name,
                a.version_name = $version_name,
                a.version_code = $version_code,
                a.min_sdk = $min_sdk,
                a.target_sdk = $target_sdk,
                a.main_activity = $main_activity,
                a.md5 = $md5,
                a.file_size = $file_size,
                a.analysis_id = $analysis_id
        """, {
            "sha256": meta.sha256,
            "package_name": meta.package_name,
            "version_name": meta.version_name,
            "version_code": meta.version_code,
            "min_sdk": meta.min_sdk,
            "target_sdk": meta.target_sdk,
            "main_activity": meta.main_activity,
            "md5": meta.md5,
            "file_size": meta.file_size,
            "analysis_id": analysis_id,
        })

        apk_node_id = node_id_counter
        vis_nodes.append({
            "id": apk_node_id,
            "label": meta.package_name or "APK",
            "group": "apk",
            "title": f"Package: {meta.package_name}\nSHA256: {meta.sha256[:16]}...",
            "size": 40,
        })
        node_id_counter += 1

        # ── Create Permission nodes ────────────────────
        for perm in result.permissions:
            session.run("""
                MERGE (p:Permission {name: $name})
                SET p.protection_level = $level,
                    p.is_suspicious = $suspicious
                WITH p
                MATCH (a:APK {sha256: $sha256})
                MERGE (a)-[:REQUESTS_PERMISSION]->(p)
            """, {
                "name": perm.name,
                "level": perm.protection_level,
                "suspicious": perm.is_suspicious,
                "sha256": meta.sha256,
            })

            perm_node_id = node_id_counter
            short_name = perm.name.split(".")[-1]
            vis_nodes.append({
                "id": perm_node_id,
                "label": short_name,
                "group": "permission_dangerous" if perm.is_suspicious else "permission_normal",
                "title": f"{perm.name}\n{perm.description}",
                "size": 20 if perm.is_suspicious else 12,
            })
            vis_edges.append({
                "from": apk_node_id,
                "to": perm_node_id,
                "label": "REQUESTS",
                "color": "#ef4444" if perm.is_suspicious else "#6b7280",
            })
            node_id_counter += 1

        # ── Create suspicious API call nodes ───────────
        for api_call in result.suspicious_api_calls:
            session.run("""
                MERGE (api:APICall {name: $name})
                SET api.category = $category,
                    api.severity = $severity
                WITH api
                MATCH (a:APK {sha256: $sha256})
                MERGE (a)-[:INVOKES_API {method: $method}]->(api)
            """, {
                "name": api_call.api_call,
                "category": api_call.category,
                "severity": api_call.severity,
                "method": api_call.method,
                "sha256": meta.sha256,
            })

            api_node_id = node_id_counter
            vis_nodes.append({
                "id": api_node_id,
                "label": api_call.api_call[:30],
                "group": f"api_{api_call.severity}",
                "title": f"API: {api_call.api_call}\nCategory: {api_call.category}\nSeverity: {api_call.severity}\nCaller: {api_call.method}",
                "size": 15,
            })
            vis_edges.append({
                "from": apk_node_id,
                "to": api_node_id,
                "label": api_call.category,
                "color": _severity_color(api_call.severity),
            })
            node_id_counter += 1

        # ── Create URL nodes ──────────────────────────
        for url in result.extracted_urls[:20]:  # Cap at 20
            session.run("""
                MERGE (u:URL {value: $url})
                WITH u
                MATCH (a:APK {sha256: $sha256})
                MERGE (a)-[:CONNECTS_TO]->(u)
            """, {"url": url, "sha256": meta.sha256})

            url_node_id = node_id_counter
            vis_nodes.append({
                "id": url_node_id,
                "label": url[:40],
                "group": "url",
                "title": f"URL: {url}",
                "size": 12,
            })
            vis_edges.append({
                "from": apk_node_id,
                "to": url_node_id,
                "label": "CONNECTS_TO",
                "color": "#f59e0b",
            })
            node_id_counter += 1

        # ── Create IP nodes ───────────────────────────
        for ip in result.extracted_ips[:20]:
            session.run("""
                MERGE (ip:IPAddress {value: $ip})
                WITH ip
                MATCH (a:APK {sha256: $sha256})
                MERGE (a)-[:CONNECTS_TO]->(ip)
            """, {"ip": ip, "sha256": meta.sha256})

            ip_node_id = node_id_counter
            vis_nodes.append({
                "id": ip_node_id,
                "label": ip,
                "group": "ip",
                "title": f"IP Address: {ip}",
                "size": 12,
            })
            vis_edges.append({
                "from": apk_node_id,
                "to": ip_node_id,
                "label": "CONNECTS_TO",
                "color": "#f59e0b",
            })
            node_id_counter += 1

    return {"nodes": vis_nodes, "edges": vis_edges}


def _generate_offline_graph(analysis_id: str, result: StaticAnalysisResult) -> dict:
    """Generate vis.js graph data without Neo4j (offline mode)."""
    vis_nodes = []
    vis_edges = []
    node_id = 0

    # APK node
    apk_id = node_id
    vis_nodes.append({
        "id": apk_id,
        "label": result.metadata.package_name or "APK",
        "group": "apk",
        "title": f"Package: {result.metadata.package_name}\nSHA256: {result.metadata.sha256[:16]}...",
        "size": 40,
    })
    node_id += 1

    # Permission nodes
    for perm in result.permissions:
        pid = node_id
        short_name = perm.name.split(".")[-1]
        vis_nodes.append({
            "id": pid,
            "label": short_name,
            "group": "permission_dangerous" if perm.is_suspicious else "permission_normal",
            "title": f"{perm.name}\n{perm.description}",
            "size": 20 if perm.is_suspicious else 12,
        })
        vis_edges.append({
            "from": apk_id,
            "to": pid,
            "label": "REQUESTS",
            "color": "#ef4444" if perm.is_suspicious else "#6b7280",
        })
        node_id += 1

    # API call nodes
    for api_call in result.suspicious_api_calls:
        aid = node_id
        vis_nodes.append({
            "id": aid,
            "label": api_call.api_call[:30],
            "group": f"api_{api_call.severity}",
            "title": f"API: {api_call.api_call}\nCategory: {api_call.category}\nSeverity: {api_call.severity}",
            "size": 15,
        })
        vis_edges.append({
            "from": apk_id,
            "to": aid,
            "label": api_call.category,
            "color": _severity_color(api_call.severity),
        })
        node_id += 1

    # URL nodes
    for url in result.extracted_urls[:20]:
        uid = node_id
        vis_nodes.append({
            "id": uid,
            "label": url[:40],
            "group": "url",
            "title": f"URL: {url}",
            "size": 12,
        })
        vis_edges.append({
            "from": apk_id,
            "to": uid,
            "label": "CONNECTS_TO",
            "color": "#f59e0b",
        })
        node_id += 1

    # IP nodes
    for ip in result.extracted_ips[:20]:
        iid = node_id
        vis_nodes.append({
            "id": iid,
            "label": ip,
            "group": "ip",
            "title": f"IP: {ip}",
            "size": 12,
        })
        vis_edges.append({
            "from": apk_id,
            "to": iid,
            "label": "CONNECTS_TO",
            "color": "#f59e0b",
        })
        node_id += 1

    return {"nodes": vis_nodes, "edges": vis_edges}


def _severity_color(severity: str) -> str:
    """Map severity to edge color."""
    return {
        "critical": "#dc2626",
        "high": "#ef4444",
        "medium": "#f59e0b",
        "low": "#22c55e",
    }.get(severity, "#6b7280")


def run_cypher(query: str, params: Optional[dict] = None) -> list[dict]:
    """Execute an arbitrary Cypher query and return results as dicts."""
    with get_session() as session:
        if session is None:
            return []
        result = session.run(query, params or {})
        return [dict(record) for record in result]


def get_graph_schema() -> str:
    """Return a text description of the graph schema for LLM context."""
    return """
Neo4j Graph Schema for GAGMA Malware Knowledge Graph:

NODE LABELS:
- (:APK) - properties: sha256, md5, package_name, version_name, version_code, min_sdk, target_sdk, main_activity, file_size, analysis_id
- (:Permission) - properties: name, protection_level (normal/dangerous), is_suspicious (boolean)
- (:APICall) - properties: name, category (sms/crypto/network/reflection/exec/data_access/device_info/overlay/accessibility/persistence), severity (low/medium/high/critical)
- (:URL) - properties: value
- (:IPAddress) - properties: value
- (:Class) - properties: name
- (:Method) - properties: name, class_name

RELATIONSHIPS:
- (:APK)-[:REQUESTS_PERMISSION]->(:Permission)
- (:APK)-[:INVOKES_API {method: string}]->(:APICall)
- (:APK)-[:CONNECTS_TO]->(:URL)
- (:APK)-[:CONNECTS_TO]->(:IPAddress)
- (:APK)-[:CONTAINS_CLASS]->(:Class)
- (:Class)-[:HAS_METHOD]->(:Method)
- (:Method)-[:CALLS]->(:Method)
- (:Method)-[:INVOKES_API]->(:APICall)

EXAMPLE QUERIES:
1. Find all dangerous permissions: MATCH (a:APK)-[:REQUESTS_PERMISSION]->(p:Permission {is_suspicious: true}) RETURN p.name
2. Find suspicious API calls: MATCH (a:APK)-[:INVOKES_API]->(api:APICall) WHERE api.severity IN ['high', 'critical'] RETURN api.name, api.category
3. Find network connections: MATCH (a:APK)-[:CONNECTS_TO]->(target) RETURN labels(target)[0] as type, target.value as target
"""
