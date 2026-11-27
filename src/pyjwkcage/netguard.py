"""Offline HTTPS endpoint and IP literal policy checks.

This module never resolves DNS and never opens a socket. It exists so a token
supplied key URL cannot smuggle an obvious loopback, private-network or cloud
metadata target past the JOSE layer.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_DEC = re.compile(r"^[0-9]+$")
_HEX = re.compile(r"^0[xX][0-9A-Fa-f]+$")
_OCT = re.compile(r"^0[0-7]+$")
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NUMERIC_HOST = re.compile(r"^[0-9A-Fa-fxX.]+$")

_IPV4_BLOCKED = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "169.254.169.254/32",
        "169.254.170.2/32",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)

_IPV6_BLOCKED = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "fd00:ec2::254/128",
        "::/128",
        "::1/128",
        "::/96",
        "::ffff:0:0/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:2::/48",
        "2001:3::/32",
        "2001:10::/28",
        "2001:20::/28",
        "2001:30::/28",
        "2001:db8::/32",
        "2002::/16",
        "2620:4f:8000::/48",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.goog",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
_BLOCKED_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".localdomain",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".onion",
)


def _numeric_piece(text: str) -> Optional[Tuple[int, int]]:
    if _HEX.match(text):
        return int(text[2:], 16), 16
    if len(text) > 1 and text.startswith("0"):
        if not _OCT.match(text):
            return None
        return int(text[1:] or "0", 8), 8
    if _DEC.match(text):
        return int(text, 10), 10
    return None


def parse_legacy_ipv4(host: object) -> Optional[ipaddress.IPv4Address]:
    """Parse dotted and integer legacy IPv4 forms without silent wrapping."""
    if not isinstance(host, str) or not host or len(host) > 64 or "%" in host:
        return None
    pieces = host.split(".")
    if len(pieces) < 1 or len(pieces) > 4 or any(not piece for piece in pieces):
        return None
    widths = {4: (8, 8, 8, 8), 3: (8, 8, 16), 2: (8, 24), 1: (32,)}[len(pieces)]
    value = 0
    for piece, width in zip(pieces, widths):
        parsed = _numeric_piece(piece)
        if parsed is None:
            return None
        number, _base = parsed
        if number < 0 or number >= (1 << width):
            return None
        value = (value << width) | number
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def _ipv6_groups(address: ipaddress.IPv6Address) -> Tuple[int, ...]:
    packed = address.packed
    return tuple(int.from_bytes(packed[index:index + 2], "big") for index in range(0, 16, 2))


def ipv6_embedded_ipv4(address: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Extract an IPv4 payload from common IPv6 transition mechanisms."""
    groups = _ipv6_groups(address)
    if groups[:5] == (0, 0, 0, 0, 0) and groups[5] == 0xFFFF:
        return ipaddress.IPv4Address((groups[6] << 16) | groups[7])
    if groups[:4] == (0, 0, 0, 0) and groups[4] == 0xFFFF and groups[5] == 0:
        return ipaddress.IPv4Address((groups[6] << 16) | groups[7])
    if groups[:6] == (0, 0, 0, 0, 0, 0) and int(address) not in (0, 1):
        return ipaddress.IPv4Address((groups[6] << 16) | groups[7])
    if groups[:6] == (0x0064, 0xFF9B, 0, 0, 0, 0):
        return ipaddress.IPv4Address((groups[6] << 16) | groups[7])
    if groups[0] == 0x2002:
        return ipaddress.IPv4Address((groups[1] << 16) | groups[2])
    if groups[0] == 0x2001 and groups[1] == 0:
        obfuscated = (groups[6] << 16) | groups[7]
        return ipaddress.IPv4Address(obfuscated ^ 0xFFFFFFFF)
    if groups[4] in (0x0000, 0x0200) and groups[5] == 0x5EFE:
        return ipaddress.IPv4Address((groups[6] << 16) | groups[7])
    return None


def is_transition_ipv6(address: ipaddress.IPv6Address) -> bool:
    return ipv6_embedded_ipv4(address) is not None


def ip_block_reason(address: IPAddress) -> Optional[str]:
    """Return why an IP is forbidden, or None when it is globally public."""
    if isinstance(address, ipaddress.IPv6Address):
        if is_transition_ipv6(address):
            embedded = ipv6_embedded_ipv4(address)
            if embedded is not None and ip_block_reason(embedded) is not None:
                return "IPv6 transition encoding embeds a non-public IPv4 address"
            return "IPv6 transition encoding is ambiguous across network parsers"
        for network in _IPV6_BLOCKED:
            if address in network:
                return "IP address is in a blocked IPv6 special-purpose range"
        if int(address) < int(ipaddress.IPv6Address("2000::")) or int(address) >= int(ipaddress.IPv6Address("4000::")):
            return "IP address is outside globally routable IPv6 unicast space"
        if address.is_multicast or address.is_loopback or address.is_link_local or address.is_unspecified or address.is_reserved:
            return "IP address is in a non-public IPv6 class"
        return None
    for network in _IPV4_BLOCKED:
        if address in network:
            return "IP address is in a blocked IPv4 special-purpose range"
    if address.is_multicast or address.is_loopback or address.is_link_local or address.is_unspecified or address.is_reserved:
        return "IP address is in a non-public IPv4 class"
    return None


def parse_ip_literal(host: object) -> Optional[IPAddress]:
    if not isinstance(host, str) or not host or len(host) > 128:
        return None
    text = host.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        return None
    if ":" in text:
        try:
            return ipaddress.IPv6Address(text)
        except ValueError:
            return None
    return parse_legacy_ipv4(text)


def canonical_host(host: str) -> str:
    text = host.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    while text.endswith("."):
        text = text[:-1]
    return text


def audit_https_url(url: object) -> Optional[Tuple[str, str]]:
    """Audit a remote key URL offline.

    Returns ``None`` for a syntactically canonical HTTPS URL on a public host,
    otherwise ``(code, message)``. DNS names cannot be proven public offline,
    so deployments must still avoid token-controlled fetching or add resolver
    pinning in a separate layer.
    """
    if not isinstance(url, str):
        return ("INVALID_URL", "remote key URL must be a string")
    if not url or len(url) > 2048:
        return ("INVALID_URL", "remote key URL length is invalid")
    if url != url.strip() or any(ord(char) < 0x21 or 0x7F <= ord(char) <= 0x9F for char in url):
        return ("INVALID_URL", "remote key URL contains whitespace or control characters")
    if "\\" in url or "\x00" in url:
        return ("INVALID_URL", "remote key URL contains an ambiguous separator")
    if not url.startswith("https://"):
        return ("UNSAFE_SCHEME", "remote key URL must use lowercase canonical https")
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
    except ValueError:
        return ("INVALID_URL", "remote key URL cannot be parsed")
    if parts.scheme != "https" or not parts.netloc:
        return ("INVALID_URL", "remote key URL must have an HTTPS authority")
    if parts.fragment:
        return ("INVALID_URL", "remote key URL must not contain a fragment")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        return ("USERINFO_FORBIDDEN", "remote key URL must not contain credentials or authority confusion")
    authority = parts.netloc
    if authority.endswith(":"):
        return ("INVALID_PORT", "remote key URL port is empty")
    port_text = None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return ("INVALID_URL", "remote key URL IPv6 brackets are malformed")
        remainder = authority[closing + 1:]
        if remainder.startswith(":"):
            port_text = remainder[1:]
        elif remainder:
            return ("INVALID_URL", "remote key URL authority is malformed")
    elif authority.count(":") > 1:
        return ("INVALID_URL", "remote key URL IPv6 literal must use brackets")
    elif ":" in authority:
        port_text = authority.rsplit(":", 1)[1]
    if port_text is not None:
        if not port_text.isdigit() or (len(port_text) > 1 and port_text.startswith("0")):
            return ("INVALID_PORT", "remote key URL port is not canonical")
    host = parts.hostname
    if not host:
        return ("INVALID_URL", "remote key URL host is empty")
    if "%" in host:
        return ("INVALID_URL", "remote key URL host must not contain percent escapes or zone identifiers")
    if host.endswith(".."):
        return ("INVALID_URL", "remote key URL host contains empty labels")
    try:
        port = parts.port
    except ValueError:
        return ("INVALID_PORT", "remote key URL port is invalid")
    if port is not None and port != 443:
        return ("INVALID_PORT", "remote key URL must use the default HTTPS port")
    host = canonical_host(host)
    if not host or len(host) > 253:
        return ("INVALID_URL", "remote key URL host length is invalid")
    literal = parse_ip_literal(host)
    if literal is not None:
        reason = ip_block_reason(literal)
        if reason is not None:
            return ("PRIVATE_OR_RESERVED_IP", reason)
        return None
    if ":" in host:
        return ("INVALID_URL", "remote key URL IPv6 literal is malformed")
    if _NUMERIC_HOST.match(host):
        return ("INVALID_URL", "numeric-looking host is not a valid canonical IPv4 literal")
    if any(ord(char) > 127 for char in host):
        return ("IDNA_FORBIDDEN", "remote key URL host must be ASCII")
    labels = host.split(".")
    if len(labels) < 2:
        return ("INVALID_URL", "remote key URL host must be a multi-label public DNS name")
    if any(not label or len(label) > 63 or not _LABEL.match(label) for label in labels):
        return ("INVALID_URL", "remote key URL host contains an invalid DNS label")
    if any(label.lower().startswith("xn--") for label in labels):
        return ("IDNA_FORBIDDEN", "remote key URL host must not use punycode labels")
    if host in _BLOCKED_HOSTNAMES:
        return ("BLOCKED_HOSTNAME", "remote key URL host is a cloud or local metadata name")
    for suffix in _BLOCKED_SUFFIXES:
        if host.endswith(suffix):
            return ("BLOCKED_HOSTNAME", "remote key URL host uses a local or non-public suffix")
    return None


def is_public_ip_literal(host: object) -> bool:
    literal = parse_ip_literal(host)
    return literal is not None and ip_block_reason(literal) is None


__all__ = [
    "audit_https_url",
    "canonical_host",
    "ip_block_reason",
    "ipv6_embedded_ipv4",
    "is_public_ip_literal",
    "is_transition_ipv6",
    "parse_ip_literal",
    "parse_legacy_ipv4",
]
