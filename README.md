# apishield

Validate outbound request targets and payload limits before an HTTP client sends them.

```bash
python -m pip install apishield
```

```python
from apishield import RequestPolicy, validate_request

policy = RequestPolicy(allowed_hosts=frozenset({"api.example.com"}))
validate_request(
    "https://api.example.com/v1/items",
    policy=policy,
    headers={"Accept": "application/json"},
    body=b"{}",
)
```

The dependency-free policy rejects non-HTTPS targets by default, URL credentials, fragments, non-allow-listed hosts/ports, header injection line breaks, oversized headers, and oversized bodies. It validates a target; it does not resolve DNS or replace a network egress firewall.
