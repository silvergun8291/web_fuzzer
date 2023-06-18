from sql_injection import *

payloads = generate_payload(60)

for payload in payloads:
    print(payload)
