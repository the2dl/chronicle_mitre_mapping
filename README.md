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
