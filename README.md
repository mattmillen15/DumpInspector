# DumpInspector
Tool to audit a folder full of Secretsdump output for Service Account creds in cleartext as well as local admin reuse.

___

# Instructions:
- Run mass secretsdump against domain hosts (using hostnames as the target for the secretsdump so the output filenames include that value).
- Run DumpInspector.py from the folder containing all the secretsdump output.
- Open up DumpInspector_Results.xlsx and confirm results. Note that for local admin reuse you'll need to confirm both that the listed accounts are actually local admin and are not disabled.

___

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/5df1657a-b087-419f-b554-62d5db061d95)

![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/ca2e68e4-12f3-4070-9088-d2173f28eb36)

___
