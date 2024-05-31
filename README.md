# DumpInspector
Tool to audit a folder full of Secretsdump output for Service Account creds in cleartext as well as local admin reuse.

**NOTE: This tool doesn't sanitize the data... probably should audit the results yourself if intended for client eyes...*

___

# Usage:
- First, run mass secretsdump against domain hosts (using hostnames as the target for the secretsdump so the output filenames include that value)
- Run the tool... 
```zsh
DumpInspector.py -d <path-to-secretsdump-folder> [-o OUTPUT]
```

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/7de1ac32-86cb-400a-b5f3-9f7d73ff9b1f)

___

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/5df1657a-b087-419f-b554-62d5db061d95)

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/ca2e68e4-12f3-4070-9088-d2173f28eb36)

___
