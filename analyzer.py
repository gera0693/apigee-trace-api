import xml.etree.ElementTree as ET
from typing import Dict, Any, List


def safe_get_text(element):
    return element.text.strip() if element is not None and element.text else None


def analyze_trace(xml_content: str) -> Dict[str, Any]:
    """
    Main entry point for analyzing an Apigee Trace XML.
    Returns structured JSON for API response.
    """

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        return {
            "success": False,
            "error": f"Invalid XML format: {str(e)}"
        }

    result = {
        "success": True,
        "summary": {},
        "policies": [],
        "faults": [],
        "flows": [],
        "target": {},
        "timings": [],
        "variables": []
    }

    extract_policies(root, result)
    extract_faults(root, result)
    extract_flows(root, result)
    extract_target_info(root, result)
    extract_timings(root, result)
    extract_variables(root, result)

    build_summary(result)

    return result


# ---------------------------------------------
# SECTION EXTRACTORS
# ---------------------------------------------

def extract_policies(root, result):
    policies = root.findall(".//Policy")

    for policy in policies:
        result["policies"].append({
            "name": policy.get("name"),
            "type": policy.get("type"),
            "status": policy.get("status"),
            "executionTime": policy.get("executionTime")
        })


def extract_faults(root, result):
    faults = root.findall(".//Fault")

    for fault in faults:
        result["faults"].append({
            "name": fault.get("name"),
            "type": fault.get("type"),
            "reason": safe_get_text(fault)
        })


def extract_flows(root, result):
    flows = root.findall(".//Flow")

    for flow in flows:
        result["flows"].append({
            "name": flow.get("name"),
            "condition": flow.get("condition"),
            "status": flow.get("status")
        })


def extract_target_info(root, result):
    target = root.find(".//Target")

    if target is not None:
        result["target"] = {
            "name": target.get("name"),
            "url": safe_get_text(target.find(".//URL")),
            "responseStatus": target.get("responseStatus")
        }


def extract_timings(root, result):
    steps = root.findall(".//Step")

    for step in steps:
        result["timings"].append({
            "name": step.get("name"),
            "type": step.get("type"),
            "executionTime": step.get("executionTime")
        })


def extract_variables(root, result):
    variables = root.findall(".//Variable")

    for var in variables:
        result["variables"].append({
            "name": var.get("name"),
            "value": safe_get_text(var)
        })


# ---------------------------------------------
# SUMMARY BUILDER
# ---------------------------------------------

def build_summary(result):
    result["summary"] = {
        "totalPolicies": len(result["policies"]),
        "totalFaults": len(result["faults"]),
        "totalFlows": len(result["flows"]),
        "totalTimings": len(result["timings"]),
        "totalVariables": len(result["variables"]),
        "hasErrors": len(result["faults"]) > 0
    }
