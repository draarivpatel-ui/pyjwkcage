"""Generated adversarial vector tests.

Each vector is registered as an individual unittest method so a failure names
exactly one attack shape rather than being hidden inside a loop.
"""
from __future__ import annotations

import copy
import unittest

from pyjwkcage import audit_jwk, audit_jwks, audit_jwt_header, parse_jwk
from pyjwkcage.errors import JwkCageError

from helpers import b64u, ec_key, oct_key, okp_key, rsa_key


def add_vector_test(cls, name, function):
    function.__name__ = name
    setattr(cls, name, function)


def header_rejection_test(header):
    def test(self):
        report = audit_jwt_header(header, allow_remote_key_urls=True)
        self.assertFalse(report.ok, "accepted hostile header: " + repr(header))
    return test


def jwks_rejection_test(jwks):
    def test(self):
        report = audit_jwks(jwks)
        self.assertFalse(report.ok, "accepted hostile jwks")
    return test


def jwk_rejection_test(key):
    def test(self):
        report = audit_jwk(key)
        self.assertFalse(report.ok, "accepted hostile jwk")
    return test


class GeneratedKidInjectionTests(unittest.TestCase):
    pass


kid_cases = []
for separator in ("/", "\\"):
    for prefix in ("..", "....", "keys/..", ".%2e", "%2e%2e"):
        for suffix in ("secret", "keys/1", "admin"):
            kid_cases.append(prefix + separator + suffix)
for quote in ("'", '"', "`"):
    for payload in (
        "key{q}OR{q}1{q}={q}1",
        "key{q};DROP TABLE keys;--",
        "{q} UNION SELECT secret --",
        "key{q}/*comment*/",
        "key{q}WAITFOR DELAY",
    ):
        kid_cases.append(payload.format(q=quote))
for control in ("\t", "\n", "\r", "\x00", "\x0b", "\x0c", "\x7f"):
    for position in ("start", "middle", "end"):
        if position == "start":
            kid_cases.append(control + "key")
        elif position == "middle":
            kid_cases.append("key" + control + "1")
        else:
            kid_cases.append("key" + control)
for token in (
    "key;DROP",
    "key--comment",
    "key/*x*/",
    "key%00",
    "key%0a",
    "key%0d",
    "key(name)",
    "key,backup",
    "key|backup",
    "key<tag>",
    "key\u202ejpg",
    "key\u200b",
    "\ufeffkey",
    "key space",
    "key\ttab",
):
    kid_cases.append(token)
kid_cases.extend(["", " ", "  ", "\x00", "../", "..\\", "..", "....//keys"])

seen_kids = set()
unique_kid_cases = []
for item in kid_cases:
    if item not in seen_kids:
        seen_kids.add(item)
        unique_kid_cases.append(item)
for index, kid in enumerate(unique_kid_cases):
    add_vector_test(
        GeneratedKidInjectionTests,
        "test_kid_injection_%03d" % index,
        header_rejection_test({"alg": "RS256", "kid": kid}),
    )


class GeneratedAlgorithmTests(unittest.TestCase):
    pass


none_algorithms = ["none", "None", "NONE", "nOnE", " none", "none ", "\tnone", "none\n"]
unsupported_algorithms = [
    "",
    "HS1",
    "HS999",
    "RS1",
    "RS999",
    "ES999",
    "eddsa",
    "hs256",
    "rs256",
    "es256",
    "HS256 ",
    " RS256",
    "HSH256",
    "RSA256",
    "SHA256",
    "null",
    "undefined",
    "A128CBC",
    "RSA1_5",
    "none\x00",
]
for index, algorithm in enumerate(none_algorithms + unsupported_algorithms):
    add_vector_test(
        GeneratedAlgorithmTests,
        "test_bad_algorithm_%03d" % index,
        header_rejection_test({"alg": algorithm, "kid": "key-1"}),
    )
for index, algorithm in enumerate(("HS256", "HS384", "HS512", "RS256", "PS256", "ES256", "EdDSA")):
    def valid_algorithm_test(self, algorithm=algorithm):
        report = audit_jwt_header({"alg": algorithm, "kid": "key-1"})
        self.assertTrue(report.ok, report.to_dict())
    add_vector_test(GeneratedAlgorithmTests, "test_valid_algorithm_%03d" % index, valid_algorithm_test)


class GeneratedRemoteUrlTests(unittest.TestCase):
    pass


bad_ipv4_hosts = [
    "127.0.0.1", "127.1", "127.0.1", "2130706433", "0x7f000001", "0x7f.0.0.1",
    "0177.0.0.1", "0177.1", "10.0.0.1", "10.1", "172.16.0.1", "172.31.255.255",
    "192.168.0.1", "192.168.255.255", "169.254.169.254", "169.254.170.2",
    "100.64.0.1", "100.127.255.255", "0.0.0.0", "255.255.255.255", "224.0.0.1",
    "239.255.255.255", "240.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "192.0.0.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1",
    "198.18.0.1", "198.19.255.255", "100.100.100.200", "168.63.129.16",
]
bad_ipv6_hosts = [
    "[::1]", "[::]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::127.0.0.1]",
    "[64:ff9b::169.254.169.254]", "[64:ff9b::7f00:1]", "[64:ff9b:1::1]",
    "[2002:7f00:0001::]", "[2002:a9fe:a9fe::]", "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
    "[fe80::1]", "[fe80::1%25eth0]", "[fc00::1]", "[fd00::1]", "[ff02::1]",
    "[fd00:ec2::254]", "[100::1]", "[2001:db8::1]", "[3fff::1]", "[5f00::1]",
    "[2001:2::1]", "[2001:3::1]", "[2001:10::1]", "[2001:20::1]", "[2001:30::1]",
]
bad_dns_hosts = [
    "localhost", "localhost.", "LOCALHOST", "metadata", "metadata.goog",
    "metadata.google.internal", "metadata.google.internal.", "instance-data",
    "instance-data.ec2.internal", "kubernetes.default.svc", "service.internal",
    "host.local", "host.localhost", "host.localdomain", "host.home.arpa",
    "1.2.3.4.in-addr.arpa", "a.ip6.arpa", "hidden.onion",
]
bad_urls = []
for host in bad_ipv4_hosts + bad_ipv6_hosts + bad_dns_hosts:
    bad_urls.append("https://" + host + "/jwks.json")
    bad_urls.append("https://" + host + ":443/jwks.json")
bad_urls.extend([
    "http://example.com/jwks.json",
    "HTTPS://example.com/jwks.json",
    "file:///etc/passwd",
    "gopher://example.com/",
    "dict://example.com/",
    "ftp://example.com/jwks.json",
    "data:text/plain,keys",
    "javascript:alert(1)",
    "https://example.com:22/jwks.json",
    "https://example.com:80/jwks.json",
    "https://example.com:8080/jwks.json",
    "https://example.com:0/jwks.json",
    "https://example.com:65536/jwks.json",
    "https://user@127.0.0.1/jwks.json",
    "https://safe.example@127.0.0.1/jwks.json",
    "https://127.0.0.1@safe.example/jwks.json",
    "https://127.0.0.1\\@safe.example/jwks.json",
    "https://safe.example\\@127.0.0.1/jwks.json",
    "https://%31%32%37.0.0.1/jwks.json",
    "https://example.com./../jwks.json#fragment",
    "https://example.com/jwks.json#fragment",
    "https:///jwks.json",
    "https://",
    "https:// example.com/jwks.json",
    "https://example.com/jwks.json ",
    " https://example.com/jwks.json",
    "https://example.com\\jwks.json",
    "https://example_com/jwks.json",
    "https://-example.com/jwks.json",
    "https://example-.com/jwks.json",
    "https://exa_mple.com/jwks.json",
    "https://xn--example.com/jwks.json",
])
seen_urls = set()
unique_bad_urls = []
for item in bad_urls:
    if item not in seen_urls:
        seen_urls.add(item)
        unique_bad_urls.append(item)
for index, url in enumerate(unique_bad_urls):
    add_vector_test(
        GeneratedRemoteUrlTests,
        "test_bad_remote_url_%03d" % index,
        header_rejection_test({"alg": "RS256", "kid": "key-1", "jku": url}),
    )

for index, url in enumerate(("https://example.com/jwks.json", "https://keys.example.org:443/jwks.json")):
    def valid_remote_test(self, url=url):
        report = audit_jwt_header({"alg": "RS256", "kid": "key-1", "x5u": url}, allow_remote_key_urls=True)
        self.assertTrue(report.ok, report.to_dict())
    add_vector_test(GeneratedRemoteUrlTests, "test_valid_remote_url_%03d" % index, valid_remote_test)


class GeneratedInlineHeaderTests(unittest.TestCase):
    pass


inline_values = [
    {},
    {"kty": "RSA"},
    {"keys": []},
    ["certificate"],
    "not-a-key",
    1,
    True,
    None,
]
inline_index = 0
for field in ("jwk", "x5c"):
    for value in inline_values:
        add_vector_test(
            GeneratedInlineHeaderTests,
            "test_inline_key_injection_%03d" % inline_index,
            header_rejection_test({"alg": "RS256", "kid": "key-1", field: value}),
        )
        inline_index += 1
for field in ("jku", "x5u"):
    for value in (None, 1, True, [], {}, "", "https://127.0.0.1/"):
        add_vector_test(
            GeneratedInlineHeaderTests,
            "test_remote_reference_injection_%03d" % inline_index,
            header_rejection_test({"alg": "RS256", "kid": "key-1", field: value}),
        )
        inline_index += 1
for value in ([], ["alg"], ["kid"], ["crit"], ["exp"], ["exp", "exp"], ["jku"], [""], [1], "exp", {"exp": True}):
    add_vector_test(
        GeneratedInlineHeaderTests,
        "test_bad_crit_%03d" % inline_index,
        header_rejection_test({"alg": "RS256", "kid": "key-1", "crit": value}),
    )
    inline_index += 1
for value in ("deflate", "gzip", "", None, True, 1):
    add_vector_test(
        GeneratedInlineHeaderTests,
        "test_bad_zip_%03d" % inline_index,
        header_rejection_test({"alg": "RSA-OAEP", "enc": "A256GCM", "zip": value}),
    )
    inline_index += 1


class GeneratedAlgorithmConfusionTests(unittest.TestCase):
    pass


key_factories = {
    "oct": lambda: oct_key(),
    "rsa": lambda: rsa_key(),
    "ec": lambda: ec_key(),
    "okp": lambda: okp_key(),
}
confusion_cases = []
for key_name, factory in key_factories.items():
    for algorithm in ("HS256", "RS256", "PS256", "ES256", "EdDSA", "RSA-OAEP", "ECDH-ES"):
        key = factory()
        key["alg"] = algorithm
        valid = (
            (key_name == "oct" and algorithm == "HS256")
            or (key_name == "rsa" and algorithm in ("RS256", "PS256", "RSA-OAEP"))
            or (key_name == "ec" and algorithm in ("ES256", "ECDH-ES"))
            or (key_name == "okp" and algorithm == "EdDSA")
        )
        if not valid:
            confusion_cases.append((key_name, algorithm, key))
for index, item in enumerate(confusion_cases):
    key_name, algorithm, key = item
    add_vector_test(
        GeneratedAlgorithmConfusionTests,
        "test_confusion_%s_%03d" % (key_name, index),
        jwk_rejection_test(key),
    )


class GeneratedRsaWeaknessTests(unittest.TestCase):
    pass


rsa_cases = []
for bits in (8, 64, 512, 1024, 1536, 2047):
    rsa_cases.append(("bits" + str(bits), rsa_key(bit_length=bits)))
for exponent in ("", "AQ", "Aw", "EQ", "A5d", "AAAA", "AQA", "10001"):
    key = rsa_key()
    key["e"] = exponent
    rsa_cases.append(("exp" + repr(exponent), key))
for mutation in ("empty_n", "padded_n", "space_n", "plus_n", "slash_n", "leading_zero_n", "even_n"):
    key = rsa_key()
    if mutation == "empty_n":
        key["n"] = ""
    elif mutation == "padded_n":
        key["n"] = key["n"] + "="
    elif mutation == "space_n":
        key["n"] = key["n"][:8] + " " + key["n"][8:]
    elif mutation == "plus_n":
        key["n"] = "+" + key["n"][1:]
    elif mutation == "slash_n":
        key["n"] = "/" + key["n"][1:]
    elif mutation == "leading_zero_n":
        import base64
        raw = base64.urlsafe_b64decode(key["n"] + "=" * ((4 - len(key["n"]) % 4) % 4))
        key["n"] = b64u(b"\x00" + raw)
    elif mutation == "even_n":
        import base64
        raw = bytearray(base64.urlsafe_b64decode(key["n"] + "=" * ((4 - len(key["n"]) % 4) % 4)))
        raw[-1] = raw[-1] & 0xFE
        key["n"] = b64u(bytes(raw))
    rsa_cases.append((mutation, key))
for index, pair in enumerate(rsa_cases):
    add_vector_test(GeneratedRsaWeaknessTests, "test_rsa_weakness_%03d" % index, jwk_rejection_test(pair[1]))


class GeneratedEcWeaknessTests(unittest.TestCase):
    pass


ec_cases = []
for crv in ("P-224", "secp256k1", "brainpoolP256r1", "Ed25519", "", "p-256", " P-256"):
    key = ec_key("P-256")
    key["crv"] = crv
    ec_cases.append(("crv" + crv, key))
for crv in ("P-256", "P-384", "P-521"):
    good = ec_key(crv)
    for coordinate in ("x", "y"):
        bad = copy.deepcopy(good)
        bad[coordinate] = bad[coordinate][:-1] + ("A" if bad[coordinate][-1] != "A" else "B")
        ec_cases.append((crv + coordinate + "mutated", bad))
        short = copy.deepcopy(good)
        short[coordinate] = short[coordinate][:-2]
        ec_cases.append((crv + coordinate + "short", short))
        padded = copy.deepcopy(good)
        padded[coordinate] = padded[coordinate] + "="
        ec_cases.append((crv + coordinate + "padded", padded))
wrong_curve = ec_key("P-256")
wrong_curve["alg"] = "ES384"
ec_cases.append(("wrong_algorithm", wrong_curve))
zero_x = ec_key("P-256")
zero_x["x"] = b64u(b"\x00" * 32)
ec_cases.append(("zero_x", zero_x))
zero_y = ec_key("P-256")
zero_y["y"] = b64u(b"\x00" * 32)
ec_cases.append(("zero_y", zero_y))
for index, pair in enumerate(ec_cases):
    add_vector_test(GeneratedEcWeaknessTests, "test_ec_weakness_%03d" % index, jwk_rejection_test(pair[1]))


class GeneratedUseAndOpsTests(unittest.TestCase):
    pass


use_ops_cases = []
for use in ("", "SIG", "sig ", "encryption", "sign", "verify", "none", "enc"):
    key = rsa_key()
    key["use"] = use
    use_ops_cases.append(("use" + repr(use), key))
for ops in (
    [],
    ["encrypt"],
    ["decrypt"],
    ["wrapKey"],
    ["unwrapKey"],
    ["sign"],
    ["verify", "encrypt"],
    ["sign", "decrypt"],
    ["verify", "verify"],
    ["unknown"],
    ["verify "],
    ["VERIFY"],
    "verify",
    {"op": "verify"},
    [None],
    [1],
):
    key = rsa_key()
    key["key_ops"] = ops
    use_ops_cases.append(("ops" + repr(ops), key))
both = rsa_key()
both["use"] = "enc"
both["key_ops"] = ["verify"]
use_ops_cases.append(("use_enc_ops_verify", both))
for index, pair in enumerate(use_ops_cases):
    add_vector_test(GeneratedUseAndOpsTests, "test_use_ops_%03d" % index, jwk_rejection_test(pair[1]))


class GeneratedJwksStructureTests(unittest.TestCase):
    pass


jwks_cases = []
for document in (
    {},
    {"keys": []},
    {"keys": {}},
    {"keys": None},
    {"keys": "not-a-list"},
    {"keys": [None]},
    {"keys": [1]},
    {"keys": ["key"]},
    {"keys": [rsa_key()], "extra": True},
    {"keys": [rsa_key()], "jwks_uri": "https://example.com/"},
):
    jwks_cases.append(document)
for size in (2, 3, 5):
    jwks_cases.append({"keys": [rsa_key("same") for _index in range(size)]})
for left, right in (("KeyA", "keya"), ("ABC", "abc"), ("key-1", "KEY-1")):
    jwks_cases.append({"keys": [rsa_key(left), rsa_key(right)]})
for index in range(20):
    first = rsa_key("shared-%02d" % index)
    second = rsa_key("shared-%02d" % index)
    jwks_cases.append({"keys": [first, second]})
missing = rsa_key("")
missing.pop("kid")
missing2 = rsa_key("")
missing2.pop("kid")
jwks_cases.append({"keys": [missing, missing2]})
for index, document in enumerate(jwks_cases):
    add_vector_test(GeneratedJwksStructureTests, "test_bad_jwks_%03d" % index, jwks_rejection_test(document))


class GeneratedBase64AndJsonTests(unittest.TestCase):
    pass


base64_mutations = []
for field in ("n", "e"):
    for value in ("", "=", "AA=", "A", "A AA", "AA AA", "AA+AA", "AA/AA", "AA\x00AA", None, 1, [], {}):
        key = rsa_key()
        key[field] = value
        base64_mutations.append((field, value, key))
for index, item in enumerate(base64_mutations):
    add_vector_test(GeneratedBase64AndJsonTests, "test_bad_base64_%03d" % index, jwk_rejection_test(item[2]))

json_texts = [
    "",
    "null",
    "[]",
    "1",
    '"text"',
    "{",
    '{"kty":"RSA",}',
    '{"kty":"RSA","kty":"RSA"}',
    '{"kty":"RSA","n":NaN}',
    '{"kty":"RSA","n":Infinity}',
    '\ufeff{"kty":"RSA"}',
    '{"kty":"RSA"}\x00',
    '{"kty":"RSA","kid":"bad\x00kid"}',
]
for index, text in enumerate(json_texts):
    def bad_json_test(self, text=text):
        try:
            parse_jwk(text, allow_private=True)
        except JwkCageError:
            return
        self.fail("accepted malformed json or malformed key")
    add_vector_test(GeneratedBase64AndJsonTests, "test_bad_json_%03d" % index, bad_json_test)

for depth in (25, 30, 40):
    def deep_json_test(self, depth=depth):
        nested = {}
        current = nested
        for _index in range(depth):
            current["x"] = {}
            current = current["x"]
        try:
            parse_jwk(nested, allow_private=True)
        except JwkCageError:
            return
        self.fail("accepted deeply nested json")
    add_vector_test(GeneratedBase64AndJsonTests, "test_deep_json_%03d" % depth, deep_json_test)


if __name__ == "__main__":
    unittest.main()
