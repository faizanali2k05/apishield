from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse
from collections.abc import Mapping


@dataclass(frozen=True)
class RequestPolicy:
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_ports: frozenset[int] = field(default_factory=frozenset)
    max_body_bytes: int = 5 * 1024 * 1024
    max_header_bytes: int = 64 * 1024
    require_https: bool = True


def _port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc


def validate_url(url: str, policy: RequestPolicy) -> None:
    """Validate a request target before an HTTP client opens a connection."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must include an HTTP(S) scheme and host")
    if policy.require_https and parsed.scheme != "https":
        raise ValueError("HTTPS is required by this policy")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to servers and are not allowed")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    allowed_hosts = {host.lower().rstrip(".") for host in policy.allowed_hosts}
    if allowed_hosts and hostname not in allowed_hosts:
        raise ValueError(f"host {hostname!r} is not allow-listed")
    port = _port(parsed)
    if policy.allowed_ports and (port or (443 if parsed.scheme == "https" else 80)) not in policy.allowed_ports:
        raise ValueError(f"port {port!r} is not allow-listed")


def validate_headers(headers: Mapping[str, str], policy: RequestPolicy) -> None:
    """Reject malformed header values and enforce a total encoded size."""

    total = 0
    for name, value in headers.items():
        if not name or "\r" in name or "\n" in name:
            raise ValueError("header names must not be empty or contain line breaks")
        if "\r" in value or "\n" in value:
            raise ValueError(f"header {name!r} contains a line break")
        total += len(str(name).encode("utf-8")) + len(str(value).encode("utf-8"))
    if total > policy.max_header_bytes:
        raise ValueError(f"headers exceed {policy.max_header_bytes} bytes")


def validate_body(body: bytes | bytearray | memoryview, policy: RequestPolicy) -> None:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    if policy.max_body_bytes < 0:
        raise ValueError("max_body_bytes must be non-negative")
    if len(body) > policy.max_body_bytes:
        raise ValueError(f"body exceeds {policy.max_body_bytes} bytes")


def validate_request(
    url: str,
    *,
    policy: RequestPolicy,
    headers: Mapping[str, str] | None = None,
    body: bytes | bytearray | memoryview | None = None,
) -> None:
    """Validate URL, headers, and body as one preflight operation."""

    validate_url(url, policy)
    if headers is not None:
        validate_headers(headers, policy)
    if body is not None:
        validate_body(body, policy)
