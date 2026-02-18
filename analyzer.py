import xml.etree.ElementTree as ET
from typing import Dict, Any, List


def safe_text(element):
    return element.text.strip() if element is not None and element.text else None


def analyze_trace(xml_content: str) -> Dict[str, Any]:

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        return {
            "success": False,
            "error": f"Invalid XML format: {str(e)}"
        }

    result = {
        "success": True,
        "metadata": {},
        "request": {},
        "stateChanges": [],
        "flowInfo": [],
        "properties": [],
        "summary": {}
    }

    extract_metadata(root, result)
    extract_request_info(root, result)
    extract_state_changes(root, result)
    extract_flow_info(root, result)

    build_summary(result)

    return result


# ------------------------------------------------
# METADATA
# ------------------------------------------------

def extract_metadata(root, result):

    result["metadata"] = {
        "organization": safe_text(root.find("Organization")),
        "environment": safe_text(root.find("Environment")),
        "api": safe_text(root.find("API")),
        "revision": safe_text(root.find("Revision")),
        "sessionId": safe_text(root.find("SessionId")),
        "retrieved": safe_text(root.find("Retrieved"))
    }


# ------------------------------------------------
# REQUEST INFO
# ------------------------------------------------

def extract_request_info(root, result):

    request_message = root.find(".//RequestMessage")

    if request_message is None:
        return

    headers = []
    for header in request_message.findall(".//Header"):
        headers.append({
            "name": header.get("name"),
            "value": safe_text(header)
        })

    result["request"] = {
        "uri": safe_text(request_message.find("URI")),
        "verb": safe_text(request_message.find("Verb")),
        "headers": headers
    }


# ------------------------------------------------
# STATE CHANGES
# ------------------------------------------------

def extract_state_changes(root, result):

    state_points = root.findall(".//Point[@id='StateChange']")

    for point in state_points:
        debug_info = point.find("DebugInfo")
        timestamp = safe_text(debug_info.find("Timestamp")) if debug_info else None

        properties = []
        for prop in point.findall(".//Property"):
            properties.append({
                "name": prop.get("name"),
                "value": safe_text(prop)
            })

        result["stateChanges"].append({
            "timestamp": timestamp,
            "properties": properties
        })


# ------------------------------------------------
# FLOW INFO
# ------------------------------------------------

def extract_flow_info(root, result):

    flow_points = root.findall(".//Point[@id='FlowInfo']")

    for point in flow_points:

        debug_info = point.find("DebugInfo")
        timestamp = safe_text(debug_info.find("Timestamp")) if debug_info else None

        properties = []
        for prop in point.findall(".//Property"):
            properties.append({
                "name": prop.get("name"),
                "value": safe_text(prop)
            })

        result["flowInfo"].append({
            "timestamp": timestamp,
            "properties": properties
        })


# ------------------------------------------------
# SUMMARY
# ------------------------------------------------

def build_summary(result):

    result["summary"] = {
        "totalStateChanges": len(result["stateChanges"]),
        "totalFlowInfoPoints": len(result["flowInfo"]),
        "totalHeaders": len(result["request"].get("headers", [])),
        "hasStateTransitions": len(result["stateChanges"]) > 0
    }
