# chronicle_mitre_mapping
MITRE Mapping from Rules metadata to spreadsheet to manipulate and send into Chronicle for dashboarding.

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

## Sample output
```
(rule_manager)  dan@studio ~/Documents/detections/rule_manager - update ~ more yara_rule_info_with_names.csv
rule_name,mitre_ta,mitre_ta_name,mitre_t1,mitre_t1_name,mitre_url
lolbin_regsvr32_and_rundll_usage,TA0005,Defense Evasion,T1218,System Binary Proxy Execution,https://attack.mitre.org/techniques/T1218/
renamed_adfind,TA0007,Discovery,T1482,Domain Trust Discovery,https://attack.mitre.org/techniques/T1482/
base64_in_registry_creation,TA0011,Command and Control,T1105,Ingress Tool Transfer,https://attack.mitre.org/techniques/T1105/
low_prevalence_file_written_and_executed,TA0005,Defense Evasion,T1027.001,Binary Padding,https://attack.mitre.org/techniques/T1027/001/
```

## Next steps
Have a label created with Google to ingest however this data looks to you and create a parser, given it's a simple data set, should be straight forward, basic CSV.
