const fs = require("fs");
const path = require("path");
const xpath = require("xpath");
const { DOMParser } = require("xmldom");

// Define namespaces from the OVAL XML file for XPath queries
const NAMESPACES = {
  "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
  "oval": "http://oval.mitre.org/XMLSchema/oval-common-5",
  "unix-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
  "red-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
  "ind-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
  "xsi": "http://www.w3.org/2001/XMLSchema-instance"
};

const select = xpath.useNamespaces(NAMESPACES);
let preprocessedData = {};

/**
 * Pre-processes all <object> definitions into a map for quick lookup.
 * @param {Document} doc - The parsed XML document.
 * @returns {Object} A map of object IDs to object data.
 */
function preprocessObjects(doc) {
  const objects = {};
  const objectNodes = select("//oval-def:objects/*", doc);

  for (const node of objectNodes) {
    const id = node.getAttribute("id");
    if (!id) continue;

    let name = "";
    // Extract name based on object type
    if (node.localName === "rpminfo_object") {
      const nameNode = select("red-def:name", node)[0];
      if (nameNode) name = nameNode.textContent;
    } else if (node.localName === "rpmverifyfile_object") {
      const filepathNode = select("red-def:filepath", node)[0];
      if (filepathNode) name = path.basename(filepathNode.textContent);
    }

    if (name) objects[id] = { name };
  }
  return objects;
}

/**
 * Pre-processes all <state> definitions into a map for quick lookup.
 * @param {Document} doc - The parsed XML document.
 * @returns {Object} A map of state IDs to an array of conditions.
 */
function preprocessStates(doc) {
  const states = {};
  const stateNodes = select("//oval-def:states/*", doc);

  for (const node of stateNodes) {
    const id = node.getAttribute("id");
    if (!id) continue;

    const conditions = [];
    for (let i = 0; i < node.childNodes.length; i++) {
      const child = node.childNodes[i];
      if (child.nodeType === 1) { // Element node
        const type = child.localName.replace("keyid", "_keyid");
        const operation = child.getAttribute("operation") || "equals";
        const value = child.textContent;
        conditions.push({ type, operation, value });
      }
    }
    if (conditions.length > 0) states[id] = { conditions };
  }
  return states;
}

/**
 * Pre-processes all <test> definitions into a map for quick lookup.
 * @param {Document} doc - The parsed XML document.
 * @returns {Object} A map of test IDs to test data (object/state refs, check type).
 */
function preprocessTests(doc) {
  const tests = {};
  const testNodes = select("//oval-def:tests/*", doc);

  for (const node of testNodes) {
    const id = node.getAttribute("id");
    if (!id) continue;

    const objectRef = select(".//red-def:object", node)[0]?.getAttribute("object_ref");
    const stateRef = select(".//red-def:state", node)[0]?.getAttribute("state_ref");
    const check = node.getAttribute("check") || "at least one";

    if (objectRef && stateRef) {
      tests[id] = { object_ref: objectRef, state_ref: stateRef, check };
    }
  }
  return tests;
}

/**
 * Parses a <criterion> element by resolving its test reference.
 * @param {Element} criterionNode - The XML node for the <criterion>.
 * @returns {Object|null} The JSON representation of the criterion.
 */
function parseCriterion(criterionNode) {
  const testRef = criterionNode.getAttribute("test_ref");
  if (!testRef) return null;

  const test = preprocessedData.tests[testRef];
  const obj = test && preprocessedData.objects[test.object_ref];
  const state = test && preprocessedData.states[test.state_ref];

  if (!test || !obj || !state) return null;

  const results = state.conditions.map(cond => [cond.type, obj.name, cond.operation, cond.value]);
  if (results.length === 0) return null;

  const resultBlock = { and: results };

  // Handle negation for checks like "none satisfy"
  if (test.check === "none satisfy") {
    return { not: resultBlock };
  }
  return resultBlock;
}

/**
 * Recursively parses a <criteria> element and its children.
 * @param {Element} criteriaNode - The XML node for the <criteria>.
 * @returns {Object} The JSON representation of the criteria logic.
 */
function parseCriteria(criteriaNode) {
  const operator = criteriaNode.getAttribute("operator").toLowerCase();
  const result = { [operator]: [] };

  for (let i = 0; i < criteriaNode.childNodes.length; i++) {
    const child = criteriaNode.childNodes[i];
    if (child.nodeType !== 1) continue;

    let parsedChild;
    if (child.localName === "criteria") {
      parsedChild = parseCriteria(child);
    } else if (child.localName === "criterion") {
      parsedChild = parseCriterion(child);
    }

    if (parsedChild) {
      result[operator].push(parsedChild);
    }
  }
  return result;
}

/**
 * Converts an OVAL XML string to the target JSON format.
 * @param {string} xmlString - The input OVAL XML content.
 * @returns {Object} The converted JSON object.
 */
function convertOvalToJson(xmlString) {
  const doc = new DOMParser().parseFromString(xmlString, "application/xml");

  preprocessedData = {
    objects: preprocessObjects(doc),
    states: preprocessStates(doc),
    tests: preprocessTests(doc)
  };

  const definitionNodes = select("/oval-def:oval_definitions/oval-def:definitions/oval-def:definition", doc);
  const advisories = [];

  for (const defNode of definitionNodes) {
    const metadataNode = select("oval-def:metadata", defNode)[0];
    const advisoryNode = select("oval-def:advisory", metadataNode)[0];

    const title = select("oval-def:title/text()", metadataNode).toString();
    const severity = select("oval-def:severity/text()", advisoryNode).toString();

    const fixes_cve = select("oval-def:reference[@source='CVE']", metadataNode)
      .map(node => node.getAttribute("ref_id"));

    const affected_cpe = select("oval-def:affected_cpe_list/oval:cpe/text()", advisoryNode)
      .map(node => node.nodeValue);

    const topCriteriaNode = select("oval-def:criteria", defNode)[0];
    // Wrap the top-level criteria object in an array to match the example output
    const criteria = topCriteriaNode ? [parseCriteria(topCriteriaNode)] : [];

    advisories.push({
      title,
      fixes_cve,
      severity,
      affected_cpe,
      criteria
    });
  }

  return { advisory: advisories };
}

/**
 * Main function to read from stdin, convert, and print to stdout.
 */
function main() {
  try {
    const xmlInput = fs.readFileSync(0, "utf-8");
    const jsonData = convertOvalToJson(xmlInput);
    console.log(JSON.stringify(jsonData, null, 2));
  } catch (error) {
    console.error("Error during OVAL to JSON conversion:", error.message);
    process.exit(1);
  }
}

// To run the script, first install dependencies:
// npm install xmldom xpath
// Then execute, piping the XML file to stdin:
// node convert.js < rhsso.oval.xml
main();