# DumpInspector
Tool to audit a folder full of Secretsdump output for Service Account creds in plaintext as well as local admin credential reuse.
<p align="center">
  <img src="https://github.com/mattmillen15/DumpInspector/assets/68832392/600bda72-5f61-4c3b-a49a-f3357db7b2dc" height="150"/>
  <img src="https://github.com/mattmillen15/DumpInspector/assets/68832392/2c423575-0018-4ba1-bc13-9f699bd99524" height="150"/>
</p>

___

This script was intended to be used to streamline domain-wide audits of locally stored credentials. For streamlining of the Secretsdump portion of this, see it's sister script [SwiftSecrets](https://github.com/mattmillen15/SwiftSecrets). 

This script will:
- Take a folder containing Secretsdump files as input. (Specifically looking for the .sam and .secrets files)
- Extracts plaintext service account credentials retreived from LSA Secrets.
- Extracts local admin credentials from SAM files.
- Removes all the junk and outputs results to a multi-tab Excel sheet.
- Optional: Uses NetExec to verify re-used accounts are valid and actually have local admin rights. (Note, this isn't a perfect science... UAC can prevent a local admin account from showing as such with remote tools such as NetExec. If you're concerned about this -> Just use the unverified results.)
- Optional: Provides a sanitized version of the .xlsx file, with the password / hash columns redacted. **NOTE: Even with the sanitize options you should probably audit the results yourself if intended for client eyes...*

___

# Usage:
- First, run mass secretsdump against all domain hosts. 
	- **Do I really need to say be careful.....? Before running a mass secretsdump be sure that their EDR isn't going to quarantine these hosts.....*
	- Use hostnames as the target for the secretsdump so the output filenames include that value --- or alternatively you can just use --lsa and --sam functionality of Netexec and point this tool to the ~/.nxc/logs directory as NetExec will include the hostname in the output filename....
	- To make this portion more efficient (at least for me), I built on an idea by an old co-worker of mine by putting together a multi-threaded Secretsdump.py wrapper in python --- you can find that here: [SwiftSecrets](https://github.com/mattmillen15/SwiftSecrets) 
- Run the tool... 
```zsh
DumpInspector.py -d <path-to-secretsdump-folder> [-o OUTPUT] [--no-verify]
```
![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/0604202b-b9cb-4694-8590-0598bc98abb5)
![image](https://github.com/mattmillen15/DumpInspector/assets/68832392/47ba8bd4-2bc4-4700-9ac8-8d4fd82c534c)
___

## Service Account Credentials in Plaintext: Understanding the Risk and Mitigation Strategies

### Why This Vulnerability Exists

Service accounts are special accounts created to run services or applications within a network. Unlike user accounts, service accounts often require higher privileges to interact with system resources and other network services. To function correctly, these accounts need to authenticate and communicate with other systems. As a result, their credentials must be stored somewhere on the local machine to allow for automatic authentication when the service starts.

Windows stores these credentials in LSA Secrets, which are accessible through the registry. While these credentials are encrypted, the encryption is reversible, meaning the local system can decrypt and use them to authenticate the service. Unfortunately, this also means that attackers who gain access to the system can decrypt and retrieve these credentials, leading to potential lateral movement within the network and further compromise.

### Why This Is a Problem

The primary issue with storing service account credentials in a reversible format is that it exposes the credentials to anyone with sufficient privileges to read the LSA Secrets. Attackers with administrative access or the ability to run specific tools can extract these credentials and use them to gain access to other systems and services within the network. This can lead to widespread compromise, especially if the service accounts have high levels of privilege.

### Remediation and Prevention Strategies

1. **Use Group Managed Service Accounts (gMSAs)**: Microsoft introduced gMSAs to address many of the security issues associated with traditional service accounts. gMSAs automatically manage password changes and eliminate the need to store credentials on local machines. By using gMSAs, you can significantly reduce the risk of credential theft from LSA Secrets.

2. **Principle of Least Privilege**: Ensure that service accounts are granted the minimum permissions necessary to perform their functions. Avoid using highly privileged accounts, such as domain admins, to run services. Instead, create dedicated service accounts with specific permissions tailored to the service's needs.

3. **Regular Auditing and Monitoring**: Implement regular audits to identify and review service accounts and their associated privileges. Monitoring tools can help detect unusual activities and potential abuse of service account credentials.

4. **Secure Storage and Handling of Credentials**: For services that cannot use gMSAs, ensure that credentials are stored securely and handled with care. Use encryption and secure storage mechanisms where possible.

___

## Local Administrator Credential Reuse: Understanding the Risk and Mitigation Strategies

### Why This Vulnerability Exists

Local administrator credential reuse occurs when the same local administrator username and password are used across multiple machines within a network. This practice simplifies management but creates a significant security risk.

### Why This Is a Problem

The reuse of local administrator credentials greatly facilitates lateral movement within a network. Once an attacker has administrative access to one machine, they can use tools to dump local administrator credentials and use them to access other machines. This can lead to a widespread compromise of the network, allowing attackers to install malware, exfiltrate data, and perform other malicious activities.

### Remediation and Prevention Strategies

1. **Unique Local Administrator Passwords**: Ensure that each machine has a unique local administrator password. This can be managed using tools such as Microsoft's Local Administrator Password Solution (LAPS), which automatically generates and manages unique passwords for local administrator accounts.

2. **Principle of Least Privilege**: Minimize the use of local administrator accounts. Only grant local administrative rights to users and services that absolutely need them. Consider using standard user accounts for everyday tasks and only elevating privileges when necessary.

3. **Regular Auditing and Monitoring**: Implement regular audits to check for the reuse of local administrator credentials across machines. Monitoring tools can help detect unusual activities and potential abuse of local administrator accounts.

4. **Secure Storage and Handling of Credentials**: Ensure that local administrator credentials are stored securely and handled with care. Use strong, complex passwords and change them regularly.

5. **Use of Multifactor Authentication (MFA)**: Where possible, implement MFA for administrative access. This adds an extra layer of security, making it more difficult for attackers to gain access using stolen credentials.
___
