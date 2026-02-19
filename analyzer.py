# analyzer.py
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import xml.etree.ElementTree as ET

# === Playbooks (enlaces de remediación) ===
PLAYBOOK_LINKS: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "status": {
        "400": [
            {"title": "HTTP 400 - Client Error Deep Dive",
            "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400"},
            {"title": "RaiseFault Policy Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/raise-fault"},
            {"title": "JSON Threat Protection Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/json-threat-protection"}
        ],

        "401": [
            {"title": "OAuthV2 Troubleshooting (Apigee)",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/oauthv2"},
            {"title": "JWT Validation & Clock Skew",
            "url": "https://cloud.google.com/apigee/docs/api-platform/security/oauth/using-jwt"},
            {"title": "VerifyAccessToken Debugging",
            "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/oauthv2-policy"}
        ],

        "403": [
            {"title": "HTTP 403 Root Causes",
            "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403"},
            {"title": "Quota Policy Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/quota"},
            {"title": "SpikeArrest Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/spike-arrest"}
        ],

        "404": [
            {"title": "Apigee Basepath & Routing Debugging",
            "url": "https://cloud.google.com/apigee/docs/api-platform/fundamentals/develop-proxies"},
        ],

        "408": [
            {"title": "HTTP 408 Request Timeout",
            "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/408"},
            {"title": "Target Timeout & Connection Settings (Apigee)",
            "url": "https://cloud.google.com/apigee/docs/api-platform/reference/endpoint-properties-reference"},
            {"title": "Backend Latency Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/runtime/timeout-errors"}
        ],

        "429": [
            {"title": "Quota Policy Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/policies/quota"},
            {"title": "SpikeArrest Configuration Guide",
            "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/spike-arrest-policy"}
        ],

        "500": [
            {"title": "500 Internal Server Error - Apigee Runtime Guide",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/runtime/500-internal-server-error"},
            {"title": "Error Handling & Fault Rules Best Practices",
            "url": "https://cloud.google.com/apigee/docs/api-platform/fundamentals/fault-handling"},
            {"title": "Debugging Proxy & Target Exceptions",
            "url": "https://cloud.google.com/apigee/docs/api-platform/debug/trace"}
        ],

        "502": [
            {"title": "502 Bad Gateway Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/runtime/502-bad-gateway"},
            {"title": "TLS Handshake Failures Explained",
            "url": "https://cloud.google.com/load-balancing/docs/ssl-certificates/troubleshooting"}
        ],

        "503": [
            {"title": "503 Service Unavailable Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/runtime/503-service-unavailable"},
            {"title": "Backend Health & Autoscaling Guide",
            "url": "https://cloud.google.com/architecture/resilient-app-engine-applications"}
        ],

        "504": [
            {"title": "504 Gateway Timeout Troubleshooting",
            "url": "https://cloud.google.com/apigee/docs/api-platform/troubleshoot/runtime/504-gateway-timeout"},
            {"title": "Timeout Configuration (Proxy & Target)",
            "url": "https://cloud.google.com/apigee/docs/api-platform/reference/endpoint-properties-reference"}
        ],
    },
    "policy": {
        "VerifyAccessToken": [
            {"title": "Apigee OAuthV2 VerifyAccessToken", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/oauthv2-policy"}
        ],
        "VerifyAPIKey": [
            {"title": "Apigee API Key Verification", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/verify-api-key-policy"}
        ],
        "SpikeArrest": [
            {"title": "Apigee SpikeArrest Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/spike-arrest-policy"}
        ],
        "Quota": [
            {"title": "Apigee Quota Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/quota-policy"}
        ],
        "AccessControl": [
            {"title": "Apigee AccessControl Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/access-control-policy"}
        ],
        "RaiseFault": [
            {"title": "Apigee RaiseFault Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/raise-fault-policy"}
        ],
        "JSONThreatProtection": [
            {"title": "JSON Threat Protection", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/json-threat-protection-policy"}
        ],
        "XMLThreatProtection": [
            {"title": "XML Threat Protection", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/xml-threat-protection-policy"}
        ],
        "ServiceCallout": [
            {"title": "Apigee ServiceCallout Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/service-callout-policy"}
        ],
        "AssignMessage": [
            {"title": "Apigee AssignMessage Policy", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/assign-message-policy"}
        ],
        "CORS": [
            {"title": "CORS in Apigee", "url": "https://cloud.google.com/apigee/docs/api-platform/cors/enable-cors"}
        ],
        "TargetServer": [
            {"title": "TargetServers & TLS", "url": "https://cloud.google.com/apigee/docs/api-platform/targets/using-target-servers"}
        ],
        "OAuthV2": [
            {"title": "OAuthV2 Policy Overview", "url": "https://cloud.google.com/apigee/docs/api-platform/reference/policies/oauthv2-policy"}
        ],
    },
}

SLOW_THRESHOLD_MS = 100.0  # umbral para marcar elementos "lentos"


# -------------------- utilidades internas --------------------
def _text(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""


def _first_text_by_tag_contains(root: ET.Element, substrings: List[str]) -> Optional[str]:
    for el in root.iter():
        t = el.tag.lower()
        if any(s in t for s in substrings):
            val = _text(el)
            if val:
                return val
    return None


def _collect_headers(root: ET.Element) -> Dict[str, str]:
    """
    Busca headers en estructuras comunes de trace Apigee:
    - Nodos cuyo tag contiene 'header' o 'httpheader' (y atributo name/key)
    - Pares <entry><name>..</name><value>..</value></entry>
    """
    headers: Dict[str, str] = {}

    for el in root.iter():
        t = el.tag.lower()

        # Formato típico <Header name="Host">example.com</Header>
        if "header" in t or "httpheader" in t or (t.endswith("header") and el.get("name")):
            name = (el.get("name") or el.get("key") or "").strip()
            if name:
                headers[name.lower()] = _text(el)

        # Formato tipo map: <entry><name>Host</name><value>example</value></entry>
        if t.endswith("entry"):
            name_el = None
            value_el = None
            for child in list(el):
                ct = child.tag.lower()
                if "name" in ct:
                    name_el = child
                if "value" in ct:
                    value_el = child
            if name_el is not None and value_el is not None:
                n = _text(name_el).lower()
                v = _text(value_el)
                if n:
                    headers[n] = v

    return headers


# -------------------- analizadores --------------------
def _analyze_request_response(root: ET.Element) -> Dict[str, Any]:
    data = {
        "method": "Unknown",
        "uri": "Unknown",
        "url": "Unknown",
        "status_code": "Unknown",
        "reason": "",
        "message": "",
        "headers": {},
    }

    m = _first_text_by_tag_contains(root, ["method", "verb"])
    if m:
        data["method"] = m

    u = _first_text_by_tag_contains(root, ["uri", "path", "requesturi", "requestpath"])
    if u:
        data["uri"] = u

    sc = _first_text_by_tag_contains(root, ["statuscode", "status-code", "status"])
    if sc:
        data["status_code"] = sc

    rs = _first_text_by_tag_contains(root, ["reasonphrase", "reason", "statusmessage"])
    if rs:
        data["reason"] = rs

    msg = _first_text_by_tag_contains(root, ["faultstring", "fault", "message", "error"])
    if msg:
        data["message"] = msg

    headers = _collect_headers(root)
    data["headers"] = headers

    host = headers.get("host") or headers.get(":authority")
    scheme = headers.get("x-forwarded-proto") or headers.get(":scheme") or headers.get("forwarded-proto") or "https"

    if host and data["uri"] and data["uri"] != "Unknown":
        if data["uri"].startswith(("http://", "https://")):
            data["url"] = data["uri"]
        else:
            data["url"] = f"{scheme}://{host}{data['uri']}"
    elif host:
        data["url"] = f"{scheme}://{host}"

    return data


def _analyze_policies(root: ET.Element) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Devuelve (policies, failed_policies)
    """
    policies: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []

    for el in root.iter():
        tag = el.tag.lower()
        if any(k in tag for k in ["policy", "step", "result"]):
            name = el.get("name") or el.get("PolicyName") or el.get("DisplayName") or ""
            ptype = el.get("type") or el.get("PolicyType") or ""
            status = el.get("status") or el.get("Status") or ""
            ex_time = el.get("executionTime") or el.get("time") or el.get("duration") or ""

            # Busca subnodos para completar info si no vino por atributo
            for child in list(el):
                ct = child.tag.lower()
                if not name and "name" in ct:
                    name = _text(child)
                if not ptype and any(s in ct for s in ["type", "policytype"]):
                    ptype = _text(child)
                if not status and "status" in ct:
                    status = _text(child)
                if not ex_time and any(s in ct for s in ["executiontime", "time", "duration"]):
                    ex_time = _text(child)

            # Busca mensajes de error razonables dentro del nodo
            error_msg = None
            for sub in el.iter():
                st = sub.tag.lower()
                if any(s in st for s in ["faultstring", "faultreason", "message", "errormessage", "error"]):
                    text = _text(sub)
                    if text:
                        error_msg = text
                        break

            pinfo = {
                "name": name or "Unknown",
                "type": ptype or "Unknown",
                "status": status or "Unknown",
                "execution_time_ms": ex_time,
                "error_message": error_msg,
            }
            policies.append(pinfo)

            if (pinfo["status"].upper() == "FAILED") or error_msg:
                failed.append(pinfo)

    return policies, failed


def _analyze_performance(root: ET.Element) -> Dict[str, Any]:
    metrics = {"slow_policies": []}
    for el in root.iter():
        t = el.tag.lower()
        if any(k in t for k in ["duration", "time", "elapsed"]):
            try:
                val = float((_text(el) or "").strip())
                name = el.get("name") or el.get("PolicyName") or ""
                if val > SLOW_THRESHOLD_MS:
                    metrics["slow_policies"].append({"name": name or "Unknown", "time_ms": val})
            except Exception:
                # si no es numérico, ignorar
                pass
    return metrics


def _derive_causes_and_remediations(
    request: Dict[str, Any], policies: List[Dict[str, Any]]
) -> Tuple[List[str], List[str], List[Dict[str, str]]]:
    sc = str(request.get("status_code", "")).strip()
    failed_policies = [p for p in policies if p.get("status", "").upper() == "FAILED" or p.get("error_message")]

    causes: List[str] = []
    fixes: List[str] = []
    playbooks: List[Dict[str, str]] = []

    def add(c: Optional[str], f: Optional[str]):
        if c:
            causes.append(c)
        if f:
            fixes.append(f)

    # Sugerencias por status code (4xx/5xx)
    if sc.startswith("4"):
        if sc == "400":
            add("Malformed request/parameters; validation failed.",
                "Validate payload; check headers/params; review RaiseFault/Threat Protection policies.")
        elif sc == "401":
            add("Missing/invalid credentials.",
                "Verify Authorization token; check VerifyAccessToken/VerifyAPIKey; confirm clock skew for JWT.")
        elif sc == "403":
            add("Forbidden due to product/quota/role; IP restrictions or policy denial.",
                "Confirm product scopes & quota; review AccessControl/SpikeArrest; adjust CORS/allowed origins; IP whitelist.")
        elif sc == "404":
            add("Resource not found; wrong basepath or route.",
                "Check basepath routing and deployment; verify request path.")
        elif sc == "408":
            add("Client timeout.", "Retry with backoff; reduce payload; verify network connectivity.")
        elif sc == "429":
            add("Rate limit exceeded.", "Increase limits/burst; client backoff; cache or de-duplicate calls.")
        else:
            add("Client-side error via gateway/target.",
                "Inspect request, headers, payload; verify policy order and conditions.")
    elif sc.startswith("5"):
        if sc == "500":
            add("Unhandled proxy/target error.", "Check error flows; recent deployments; logs for exceptions.")
        elif sc == "502":
            add("Bad gateway or TLS handshake failure.", "Validate target URL/TLS; ciphers/protocols; target health.")
        elif sc == "503":
            add("Service unavailable/overloaded.", "Check autoscaling/health; increase timeouts; add retries/circuit breaker.")
        elif sc == "504":
            add("Gateway timeout.", "Increase target timeouts; optimize latency; cache/async patterns.")
        else:
            add("Server-side error via gateway/target.",
                "Investigate target logs; enable trace; rollback risky changes.")

    # Playbooks por status
    playbooks.extend(PLAYBOOK_LINKS.get("status", {}).get(sc, []))

    # Policies fallidas + playbooks por tipo
    for p in failed_policies:
        pname = p.get("name", "Unknown")
        ptype = p.get("type", "")
        perr = p.get("error_message") or ""
        add(
            f"Policy '{pname}' failed ({ptype}). {perr}",
            f"Fix policy '{pname}': validate configuration/variables; test with trace; check conditions & resources."
        )

        # match exacto o por coincidencia parcial
        if ptype in PLAYBOOK_LINKS.get("policy", {}):
            playbooks.extend(PLAYBOOK_LINKS["policy"][ptype])
        else:
            for key, items in PLAYBOOK_LINKS.get("policy", {}).items():
                if key.lower() in ptype.lower() or key.lower() in pname.lower():
                    playbooks.extend(items)

    # Deduplicar playbooks por URL
    seen = set()
    unique_books: List[Dict[str, str]] = []
    for b in playbooks:
        url = b.get("url")
        title = b.get("title", "Playbook")
        if url and url not in seen:
            seen.add(url)
            unique_books.append({"title": title, "url": url})

    return causes, fixes, unique_books[:15]


# -------------------- generador de reporte texto --------------------
def _generate_text_report(analysis: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append

    add("=" * 80)
    add("APIGEE TRACE SESSION ANALYSIS REPORT (Web API)")
    add("=" * 80)
    add("")

    req = analysis.get("request") or {}
    if req:
        add("REQUEST / RESPONSE SUMMARY")
        add("-" * 80)
        add(f"Method: {req.get('method', 'Unknown')}")
        add(f"URI: {req.get('uri', 'Unknown')}")
        add(f"URL: {req.get('url', 'Unknown')}")
        line = f"Status: {req.get('status_code', 'Unknown')}"
        if req.get("reason"):
            line += f" {req['reason']}"
        add(line)
        if req.get("message"):
            add(f"Message: {req['message']}")
        add("")

    policies = analysis.get("policies") or []
    if policies:
        add("POLICY EXECUTION SUMMARY")
        add("-" * 80)
        add(f"Total Policies: {len(policies)}")
        failed = [p for p in policies if p.get("status", "").upper() == "FAILED" or p.get("error_message")]
        add(f"Failed Policies: {len(failed)}")
        if failed:
            add("\nFailed Policy Details:")
            for p in failed[:20]:
                add(f" - {p.get('name', 'Unknown')} ({p.get('type', 'Unknown')})")
                add(f"   Status: {p.get('status', 'Unknown')} Time: {p.get('execution_time_ms', 'n/a')} ms")
                if p.get("error_message"):
                    add(f"   Error: {p['error_message']}")
        add("")

    perf = analysis.get("performance") or {}
    if perf.get("slow_policies"):
        add("PERFORMANCE (Slow Items > 100ms)")
        add("-" * 80)
        for sp in perf["slow_policies"][:20]:
            add(f" - {sp.get('name', 'Unknown')}: {sp.get('time_ms', '?')} ms")
        add("")

    issues = analysis.get("issues") or []
    if issues:
        add("ISSUES DETECTED")
        add("-" * 80)
        for i in issues:
            add(f"[{i.get('severity', 'INFO')}] {i.get('type', 'Unknown')}: {i.get('description', '')}")
        add("")

    if analysis.get("causes") or analysis.get("remediations"):
        add("POSSIBLE CAUSES & REMEDIATIONS")
        add("-" * 80)
        if analysis.get("causes"):
            add("Possible Causes:")
            for c in analysis["causes"][:10]:
                add(f" - {c}")
        if analysis.get("remediations"):
            add("\nSuggested Remediations:")
            for f in analysis["remediations"][:10]:
                add(f" - {f}")
        add("")

    if analysis.get("playbooks"):
        add("REMEDIATION PLAYBOOKS (links)")
        add("-" * 80)
        for b in analysis["playbooks"]:
            add(f" - {b.get('title', 'Playbook')}: {b.get('url', '')}")
        add("")

    add("=" * 80)
    add("Report Generated by analyzer.py")
    add("=" * 80)

    return "\n".join(lines)


def _extract_top_level_metadata(root):
    meta = {
        "organization": None,
        "environment": None,
        "api": None,
        "revision": None,
        "sessionId": None,
        "retrieved": None,
        # extras:
        "virtualhost": None,
        "proxyUrl": None,
    }

    # 1) Tags top-level (DebugSession children)
    tl_map = {
        "organization": ["organization"],
        "environment": ["environment"],
        "api": ["api"],
        "revision": ["revision"],
        "sessionId": ["sessionid", "session-id", "session_id"],
        "retrieved": ["retrieved"],
    }
    for el in root:
        tag = (el.tag or "").lower()
        text = (el.text or "").strip()
        for key, names in tl_map.items():
            if tag in names and text:
                meta[key] = text

    # 2) Propiedades de FlowInfo / DebugInfo / Properties
    for p in root.iter():
        t = (p.tag or "").lower()
        if not t.endswith("properties"):
            continue
        for prop in p.iter():
            if (prop.tag or "").lower().endswith("property"):
                name = (prop.get("name") or "").lower()
                val = (prop.text or "").strip()
                if not val:
                    continue
                if name == "organization.name" and not meta["organization"]:
                    meta["organization"] = val
                elif name == "environment.name" and not meta["environment"]:
                    meta["environment"] = val
                elif name == "apiproxy.name" and not meta["api"]:
                    meta["api"] = val
                elif name == "apiproxy.revision" and not meta["revision"]:
                    meta["revision"] = val
                elif name == "virtualhost.name" and not meta["virtualhost"]:
                    meta["virtualhost"] = val
                elif name == "proxy.url" and not meta["proxyUrl"]:
                    meta["proxyUrl"] = val

    return meta

# -------------------- función pública --------------------
def analyze_trace(xml_content: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analiza el contenido XML (string) de una traza Apigee y devuelve un dict.
    """
    try:
        root = ET.fromstring(xml_content)
    except Exception as e:
        return {
            "status": "error",
            "message": f"No se pudo parsear el XML: {e}",
        }

    analysis: Dict[str, Any] = {
        "request": {},
        "policies": [],
        "performance": {},
        "issues": [],
        "causes": [],
        "remediations": [],
        "playbooks": [],
        "report_text": "",
    }

    # 1) Request/Response
    req = _analyze_request_response(root)
    analysis["request"] = req

    # 2) Policies
    policies, failed = _analyze_policies(root)
    analysis["policies"] = policies

    # 3) Performance
    perf = _analyze_performance(root)
    analysis["performance"] = perf

    # 4) Issues desde policies y performance
    if failed:
        for p in failed:
            analysis["issues"].append({
                "severity": "HIGH",
                "type": "POLICY_FAILED",
                "policy": p.get("name"),
                "description": f"Policy '{p.get('name','Unknown')}' ({p.get('type','Unknown')}) failed. "
                               f"{('Error: ' + p['error_message']) if p.get('error_message') else ''}".strip()
            })

    if perf.get("slow_policies"):
        analysis["issues"].append({
            "severity": "MEDIUM",
            "type": "PERFORMANCE_ISSUE",
            "description": f"Found {len(perf['slow_policies'])} slow-executing items (> {SLOW_THRESHOLD_MS}ms)"
        })

    # 5) Si el status es 4xx/5xx, agrega issue de HTTP
    sc = str(req.get("status_code", "")).strip()
    if sc and (sc.startswith("4") or sc.startswith("5")):
        sev = "CRITICAL" if sc.startswith("5") else "HIGH"
        desc = f"HTTP {sc}{(' (' + req.get('reason','') + ')') if req.get('reason') else ''}"
        analysis["issues"].append({
            "severity": sev,
            "type": "HTTP_ERROR",
            "code": sc,
            "description": desc
        })

    # 6) Causas, remediaciones, playbooks
    causes, fixes, books = _derive_causes_and_remediations(req, policies)
    analysis["causes"] = causes
    analysis["remediations"] = fixes
    analysis["playbooks"] = books

    # 7) Reporte de texto
    analysis["report_text"] = _generate_text_report(analysis)
    
    analysis["metadata"] = _extract_top_level_metadata(root)

    # Éxito
    analysis["status"] = "ok"
    return analysis
