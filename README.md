# DumpInspector
Tool to audit a folder full of Secretsdump output for Service Account creds in plaintext as well as local admin credential reuse.
___


This script was intended to be used to streamline domain-wide audits of locally stored credentials. For streamlining of the Secretsdump portion of this, see it's sister script [SwiftSecrets](https://github.com/mattmillen15/SwiftSecrets). 

This script will:
- Take a folder containing Secretsdump files as input. (Specifically looking for the .sam and .secrets files)
- Extracts plaintext service account credentials retreived from LSA Secrets.
- Extracts local admin credentials from SAM files.
- Removes all the junk and outputs results to a multi-tab Excel sheet.

**NOTE: This tool doesn't sanitize the data... probably should audit the results yourself if intended for client eyes...*
___

# Usage:
- First, run mass secretsdump against all domain hosts. 
	- **Do I really need to say be careful.....? Before running a mass secretsdump be sure that their EDR isn't going to quarantine these hosts.....*
	- Use hostnames as the target for the secretsdump so the output filenames include that value --- or alternatively you can just use --lsa and --sam functionality of Netexec and point this tool to the ~/.nxc/logs directory as NetExec will include the hostname in the output filename....
	- To make this portion more efficient (at least for me), I built on an idea by an old co-worker of mine by putting together a multi-threaded Secretsdump.py wrapper in python --- you can find that here: [SwiftSecrets](https://github.com/mattmillen15/SwiftSecrets) 
- Run the tool... 
```zsh
DumpInspector.py -d <path-to-secretsdump-folder> [-o OUTPUT]
```

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/7de1ac32-86cb-400a-b5f3-9f7d73ff9b1f)

___

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/5df1657a-b087-419f-b554-62d5db061d95)

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/ca2e68e4-12f3-4070-9088-d2173f28eb36)

___
