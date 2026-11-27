from __future__ import annotations

import ipaddress
import unittest
from collections.abc import Mapping

from pyjwkcage import (
    JwkCageError,
    audit_jwk,
    compute_jwk_thumbprint,
    parse_jwk,
    select_verification_key,
    strip_private_material,
)
from pyjwkcage.netguard import ipv6_embedded_ipv4

from helpers import rsa_key


class DictMapping(Mapping):
    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


class HostileMapping(Mapping):
    def __getitem__(self, key):
        raise RuntimeError("hostile mapping access")

    def __iter__(self):
        return iter(["kty"])

    def __len__(self):
        return 1


class ChangingJwksMapping(Mapping):
    def __init__(self, values):
        self._values = list(values)
        self.accesses = 0

    def __getitem__(self, key):
        if key != "keys":
            raise KeyError(key)
        index = min(self.accesses, len(self._values) - 1)
        self.accesses += 1
        return self._values[index]

    def __iter__(self):
        return iter(["keys"])

    def __len__(self):
        return 1


class TestParserRobustnessRegression(unittest.TestCase):
    def test_deep_mapping_audit_returns_report_instead_of_recursion_error(self):
        nested = {}
        current = nested
        for _ in range(2000):
            current["x"] = {}
            current = current["x"]
        report = audit_jwk(nested)
        self.assertFalse(report.ok)
        self.assertIn("JSON_INVALID", report.error_codes)

    def test_deep_json_text_audit_returns_report_instead_of_recursion_error(self):
        text = '{"x":' * 2000 + "0" + "}" * 2000
        report = audit_jwk(text)
        self.assertFalse(report.ok)
        self.assertIn("JSON_INVALID", report.error_codes)

    def test_cyclic_mapping_audit_returns_report_instead_of_recursion_error(self):
        cyclic = {"kty": "RSA"}
        cyclic["self"] = cyclic
        report = audit_jwk(cyclic)
        self.assertFalse(report.ok)
        self.assertIn("JSON_INVALID", report.error_codes)

    def test_cyclic_mapping_throwing_apis_raise_stable_error(self):
        cyclic = {"kty": "RSA"}
        cyclic["self"] = cyclic
        with self.assertRaises(JwkCageError) as strip_error:
            strip_private_material(cyclic)
        self.assertEqual(strip_error.exception.code, "JSON_INVALID")
        with self.assertRaises(JwkCageError) as thumbprint_error:
            compute_jwk_thumbprint(cyclic)
        self.assertEqual(thumbprint_error.exception.code, "JSON_INVALID")

    def test_custom_mapping_valid_input_is_copied(self):
        parsed = parse_jwk(DictMapping(rsa_key()))
        self.assertEqual(parsed["kty"], "RSA")
        self.assertIsInstance(parsed, dict)

    def test_hostile_mapping_audit_returns_report_instead_of_runtime_error(self):
        report = audit_jwk(HostileMapping())
        self.assertFalse(report.ok)
        self.assertIn("JSON_INVALID", report.error_codes)

    def test_non_string_mapping_keys_are_not_stringified(self):
        for extra in ({1: "x"}, {1: "first", "1": "second"}, {("x",): "y"}):
            candidate = rsa_key()
            candidate.update(extra)
            with self.assertRaises(JwkCageError) as caught:
                parse_jwk(candidate)
            self.assertEqual(caught.exception.code, "JSON_INVALID")

    def test_key_selection_uses_the_same_snapshot_it_audited(self):
        audited_key = rsa_key("snapshot")
        weak_key = rsa_key("snapshot", bit_length=1024)
        changing = ChangingJwksMapping([[audited_key], [weak_key]])
        selected = select_verification_key(
            changing,
            {"alg": "RS256", "kid": "snapshot"},
            allowed_algs=["RS256"],
        )
        self.assertEqual(selected["n"], audited_key["n"])
        self.assertNotEqual(selected["n"], weak_key["n"])

    def test_ipv6_transition_extraction_uses_packed_bytes_on_every_python(self):
        self.assertEqual(
            ipv6_embedded_ipv4(ipaddress.IPv6Address("::ffff:127.0.0.1")),
            ipaddress.IPv4Address("127.0.0.1"),
        )
        self.assertEqual(
            ipv6_embedded_ipv4(ipaddress.IPv6Address("64:ff9b::7f00:1")),
            ipaddress.IPv4Address("127.0.0.1"),
        )


if __name__ == "__main__":
    unittest.main()
