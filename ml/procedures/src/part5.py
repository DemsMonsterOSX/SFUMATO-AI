from common import P

P("PROC-018", "Malicious Office macro", "Execution", ["T1204.002", "T1059.005"], "high", ["office", "macro", "phishing"],
  ["Word or Excel spawns cmd, PowerShell or wscript", "Document asks the user to enable content", "Macro with auto-open handlers and obfuscated strings"],
  ["Extract the macro with oledump or similar in a sandbox", "List URLs and dropped files", "Check which users received or opened the file"],
  ["Block macros from the Internet by policy", "Isolate hosts where the macro ran"],
  ["Remove dropped payloads and persistence"],
  ["Restore hosts, enforce Protected View and macro blocking"],
  ["Document copy, sandbox report, process tree"],
  ["Finance templates that use signed internal macros"])
P("PROC-058", "Theft of SSH private keys", "Credential Access", ["T1552.004"], "high", ["ssh", "keys", "linux"],
  ["Read access to ~/.ssh by an unusual process", "Key used from a new host or IP", "Keys without passphrases found in backups"],
  ["Identify which keys were exposed and where they are authorised", "Review recent logins with these keys"],
  ["Remove the public keys from authorized_keys everywhere"],
  ["Issue new keys with passphrases or certificates"],
  ["Use short-lived SSH certificates and a bastion"],
  ["auth.log, file access audit"],
  ["Backup tools reading home directories"])
P("PROC-066", "Command and control through a legitimate web service", "Command and Control", ["T1102"], "medium", ["c2", "saas", "cloud"],
  ["Regular small calls to a code-sharing, paste or chat API from a server", "API tokens embedded in malware"],
  ["Identify the account or channel used and the calling process", "Preserve content with a legal request if needed"],
  ["Block the specific account path where possible, isolate the host"],
  ["Remove the implant"],
  ["Report the abuse to the service provider"],
  ["Proxy logs, memory dump"],
  ["Developers using the same service"])
P("PROC-088", "Reflection and amplification attack", "Impact", ["T1498.002"], "high", ["ddos", "amplification", "udp"],
  ["Very large UDP responses from DNS, NTP or memcached servers aimed at one target", "Source ports 53, 123 or 11211"],
  ["Identify the reflector protocol and the victim", "Check that your own services are not used as reflectors"],
  ["Filter the source ports at the edge, engage the upstream provider"],
  ["Close open resolvers and restrict UDP services"],
  ["Remove filters after the attack ends"],
  ["Flow data, packet captures"],
  ["Large legitimate DNS answers (DNSSEC)"])
