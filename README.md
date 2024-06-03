# chronicle_mitre_mapping
MITRE Mapping from Rules metadata to spreadsheet or json to manipulate and send into Chronicle for dashboarding (or directly manipulate in a spreadsheet).

## Update metadata
Make sure your metadata includes mitre mappings, for example:

```
{
  meta:
    author = "Dan Lussier"
    description = "Look for the use of AdFind.exe, which is often used in ransomware attacks"
    Version = "1.0"
    severity = "Medium"
    mitre_ta = "TA0007"
    mitre_t1 = "T1087"
    mitre_url = "https://attack.mitre.org/techniques/T1087/"
    reference_docs = "https://thedfirreport.com/2020/05/08/adfind-recon/"

    ... rest of rule
}
```

## Download the official Chronicle Rule Manager
https://github.com/chronicle/detection-rules/tree/main/tools/rule_manager

Follow the instructions to initialize it, download your rules, they'll be stored in the `rules` folder. From there run this script (adjust folder/output name accordingly).

## Sample output (CSV)
```
(rule_manager)  dan@studio ~/Documents/detections/rule_manager - update ~ more yara_rule_info_with_names.csv
rule_name,mitre_ta,mitre_ta_name,mitre_t1,mitre_t1_name,mitre_url
lolbin_regsvr32_and_rundll_usage,TA0005,Defense Evasion,T1218,System Binary Proxy Execution,https://attack.mitre.org/techniques/T1218/
renamed_adfind,TA0007,Discovery,T1482,Domain Trust Discovery,https://attack.mitre.org/techniques/T1482/
base64_in_registry_creation,TA0011,Command and Control,T1105,Ingress Tool Transfer,https://attack.mitre.org/techniques/T1105/
```

## Sample output (JSON)
```
(rule_manager)  ✘ dan@studio  ~/Documents/detections/rule_manager   update  cat yara_rule_info_with_names.json| jq .
[
  {
    "rule_name": "lolbin_regsvr32_and_rundll_usage",
    "mitre_ta": "TA0005",
    "mitre_t1": "T1218",
    "mitre_url": "https://attack.mitre.org/techniques/T1218/",
    "mitre_ta_name": "Defense Evasion",
    "mitre_t1_name": "System Binary Proxy Execution"
  },
  {
    "rule_name": "renamed_adfind",
    "mitre_ta": "TA0007",
    "mitre_t1": "T1482",
    "mitre_url": "https://attack.mitre.org/techniques/T1482/",
    "mitre_ta_name": "Discovery",
    "mitre_t1_name": "Domain Trust Discovery"
  },
  {
    "rule_name": "base64_in_registry_creation",
    "mitre_ta": "TA0011",
    "mitre_t1": "T1105",
    "mitre_url": "https://attack.mitre.org/techniques/T1105/",
    "mitre_ta_name": "Command and Control",
    "mitre_t1_name": "Ingress Tool Transfer"
  }
]
```

## Next steps
Have a label created with Google to ingest however this data looks to you and create a parser, given it's a simple data set, should be straight forward, JSON is easier for ingest to Chronicle.
