import json
import os
import re
import requests

def extract_yara_rule_info(rule_file):
    """Extracts relevant rule information from a YARA-L file."""
    rule_info = {}
    with open(rule_file, "r") as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("rule "):
                rule_info["rule_name"] = line.split()[1].rstrip("{")
            else:
                match = re.match(r"\s*(mitre_ta|mitre_t1|mitre_url)\s*=\s*\"(.*?)\"", line, re.IGNORECASE)
                if match:
                    field_name = match.group(1).lower()
                    rule_info[field_name] = match.group(2)
    return rule_info

def fetch_mitre_data():
    """Fetches MITRE ATT&CK data in STIX format from the official source."""
    stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(stix_url)
    response.raise_for_status()  # Raise an exception if the request fails
    data = response.json()
    return {
        obj["external_references"][0]["external_id"]: obj["name"]
        for obj in data["objects"]
        if obj["type"] == "x-mitre-tactic"
    }, {
        obj["external_references"][0]["external_id"]: obj["name"]
        for obj in data["objects"]
        if obj["type"] == "attack-pattern"
    }

def main():
    rule_dir = "rules"
    json_file = "yara_rule_info_with_names.json"  # Output file changed to JSON

    mitre_tactics, mitre_techniques = fetch_mitre_data()

    # Create a list to store rule information as dictionaries
    rule_info_list = []

    for filename in os.listdir(rule_dir):
        if filename.endswith(".yaral"):
            rule_file = os.path.join(rule_dir, filename)
            rule_info = extract_yara_rule_info(rule_file)
            if rule_info:
                rule_info["mitre_ta_name"] = mitre_tactics.get(rule_info.get("mitre_ta"), "N/A")
                rule_info["mitre_t1_name"] = mitre_techniques.get(rule_info.get("mitre_t1"), "N/A")

                # Add the rule information dictionary to the list
                rule_info_list.append(rule_info)

    # Write the rule information list to a JSON file
    with open(json_file, "w") as f:
        json.dump(rule_info_list, f, indent=4)  # Format with indentation

    print("Mapping complete! Results written to:", json_file)


if __name__ == "__main__":
    main()
