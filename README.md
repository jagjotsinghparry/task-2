# OVAL XML to JSON Converter

## Structure and Flow
These scripts converts OVAL XML files into structured JSON output. It uses the lxml library in Python and xmldom in NodeJS to parse XML documents and extract information through XPath queries with predefined namespaces.

The script first preprocesses all object, state, and test definitions in the XML. Objects provide package or file names, states define conditions, and tests link objects and states together. These are stored in lookup tables for efficient reference.

When processing definitions, the script reads metadata such as title, severity, CVE references, and affected CPEs. It then recursively parses the <criteria> elements, resolving each <criterion> into a condition block that combines object names and state conditions. Logical operators like and, or, and not are preserved to represent the original structure of the XML.

Finally, the script collects all advisories into a JSON object with fields for title, CVEs, severity, affected CPEs, and evaluation criteria, and prints the result to standard output. This produces a machine-readable representation of Red Hat OVAL advisories suitable for further processing or integration.

## Running
Python: `python3 index.py < oval.xml > output.json
NodeJS: `node index.js < oval.xml > output.json