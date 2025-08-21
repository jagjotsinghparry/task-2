import sys
import json
import os
from lxml import etree

# Define namespaces from the OVAL XML file for XPath queries
NAMESPACES = {
    "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "oval": "http://oval.mitre.org/XMLSchema/oval-common-5",
    "unix-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
    "red-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
    "ind-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance"
}

preprocessed_data = {}


def preprocess_objects(doc):
    """Pre-processes all <object> definitions into a map for quick lookup."""
    objects = {}
    object_nodes = doc.xpath("//oval-def:objects/*", namespaces=NAMESPACES)

    for node in object_nodes:
        obj_id = node.get("id")
        if not obj_id:
            continue

        name = ""
        if node.tag.endswith("rpminfo_object"):
            name_node = node.xpath("red-def:name", namespaces=NAMESPACES)
            if name_node:
                name = name_node[0].text
        elif node.tag.endswith("rpmverifyfile_object"):
            filepath_node = node.xpath("red-def:filepath", namespaces=NAMESPACES)
            if filepath_node:
                name = os.path.basename(filepath_node[0].text)

        if name:
            objects[obj_id] = {"name": name}
    return objects


def preprocess_states(doc):
    """Pre-processes all <state> definitions into a map for quick lookup."""
    states = {}
    state_nodes = doc.xpath("//oval-def:states/*", namespaces=NAMESPACES)

    for node in state_nodes:
        state_id = node.get("id")
        if not state_id:
            continue

        conditions = []
        for child in node:
            if isinstance(child.tag, str):  # element node
                type_name = child.tag.split("}")[-1].replace("keyid", "_keyid")
                operation = child.get("operation") or "equals"
                value = child.text
                conditions.append({"type": type_name, "operation": operation, "value": value})

        if conditions:
            states[state_id] = {"conditions": conditions}
    return states


def preprocess_tests(doc):
    """Pre-processes all <test> definitions into a map for quick lookup."""
    tests = {}
    test_nodes = doc.xpath("//oval-def:tests/*", namespaces=NAMESPACES)

    for node in test_nodes:
        test_id = node.get("id")
        if not test_id:
            continue

        object_ref_nodes = node.xpath(".//red-def:object", namespaces=NAMESPACES)
        state_ref_nodes = node.xpath(".//red-def:state", namespaces=NAMESPACES)
        object_ref = object_ref_nodes[0].get("object_ref") if object_ref_nodes else None
        state_ref = state_ref_nodes[0].get("state_ref") if state_ref_nodes else None
        check = node.get("check") or "at least one"

        if object_ref and state_ref:
            tests[test_id] = {"object_ref": object_ref, "state_ref": state_ref, "check": check}
    return tests


def parse_criterion(criterion_node):
    """Parses a <criterion> element by resolving its test reference."""
    test_ref = criterion_node.get("test_ref")
    if not test_ref:
        return None

    test = preprocessed_data["tests"].get(test_ref)
    obj = preprocessed_data["objects"].get(test["object_ref"]) if test else None
    state = preprocessed_data["states"].get(test["state_ref"]) if test else None

    if not test or not obj or not state:
        return None

    results = [[cond["type"], obj["name"], cond["operation"], cond["value"]]
               for cond in state["conditions"]]

    if not results:
        return None

    result_block = {"and": results}

    # Handle negation for checks like "none satisfy"
    if test["check"] == "none satisfy":
        return {"not": result_block}
    return result_block


def parse_criteria(criteria_node):
    """Recursively parses a <criteria> element and its children."""
    operator = criteria_node.get("operator", "").lower()
    result = {operator: []}

    for child in criteria_node:
        if not isinstance(child.tag, str):
            continue

        parsed_child = None
        localname = child.tag.split("}")[-1]
        if localname == "criteria":
            parsed_child = parse_criteria(child)
        elif localname == "criterion":
            parsed_child = parse_criterion(child)

        if parsed_child:
            result[operator].append(parsed_child)

    return result


def convert_oval_to_json(xml_string):
    """Converts an OVAL XML string to the target JSON format."""
    doc = etree.fromstring(xml_string.encode("utf-8"))

    global preprocessed_data
    preprocessed_data = {
        "objects": preprocess_objects(doc),
        "states": preprocess_states(doc),
        "tests": preprocess_tests(doc)
    }

    definition_nodes = doc.xpath(
        "/oval-def:oval_definitions/oval-def:definitions/oval-def:definition",
        namespaces=NAMESPACES
    )
    advisories = []

    for def_node in definition_nodes:
        metadata_node = def_node.xpath("oval-def:metadata", namespaces=NAMESPACES)
        if not metadata_node:
            continue
        metadata_node = metadata_node[0]

        advisory_node = metadata_node.xpath("oval-def:advisory", namespaces=NAMESPACES)
        advisory_node = advisory_node[0] if advisory_node else None

        title_nodes = metadata_node.xpath("oval-def:title/text()", namespaces=NAMESPACES)
        title = title_nodes[0] if title_nodes else ""

        severity_nodes = advisory_node.xpath("oval-def:severity/text()", namespaces=NAMESPACES) if advisory_node else []
        severity = severity_nodes[0] if severity_nodes else ""

        fixes_cve = [node.get("ref_id")
                     for node in metadata_node.xpath("oval-def:reference[@source='CVE']", namespaces=NAMESPACES)]

        affected_cpe = [node for node in advisory_node.xpath("oval-def:affected_cpe_list/oval:cpe/text()", namespaces=NAMESPACES)] if advisory_node else []

        top_criteria_node = def_node.xpath("oval-def:criteria", namespaces=NAMESPACES)
        criteria = [parse_criteria(top_criteria_node[0])] if top_criteria_node else []

        advisories.append({
            "title": title,
            "fixes_cve": fixes_cve,
            "severity": severity,
            "affected_cpe": affected_cpe,
            "criteria": criteria
        })

    return {"advisory": advisories}


def main():
    try:
        xml_input = sys.stdin.read()
        json_data = convert_oval_to_json(xml_input)
        print(json.dumps(json_data, indent=2))
    except Exception as e:
        print("Error during OVAL to JSON conversion:", str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
