from __future__ import annotations

import copy
import json
import unittest

from pyjwkcage import (
    JwkCageError,
    audit_jwk,
    audit_jwks,
    audit_jwt_header,
    compute_jwk_thumbprint,
    parse_jwk,
    select_verification_key,
    strip_private_material,
)
from pyjwkcage.netguard import audit_https_url, parse_legacy_ipv4

from helpers import RFC7638_KEY, RFC7638_THUMBPRINT, ec_key, oct_key, okp_key, rsa_key


class TestCoreSecurity(unittest.TestCase):
    def test_rfc7638_thumbprint_vector(self):
        self.assertEqual(compute_jwk_thumbprint(RFC7638_KEY), RFC7638_THUMBPRINT)

    def test_valid_public_jwks_is_clean(self):
        report = audit_jwks({"keys": [rsa_key(), ec_key(), okp_key()]})
        self.assertTrue(report.ok, report.to_dict())
        self.assertEqual(report.error_codes, ())

    def test_parse_jwk_rejects_private_material_by_default(self):
        key = rsa_key()
        key["d"] = "AQ"
        with self.assertRaises(JwkCageError) as caught:
            parse_jwk(key)
        self.assertEqual(caught.exception.code, "PRIVATE_MATERIAL")

    def test_parse_jwk_allows_private_only_explicitly(self):
        key = rsa_key()
        key["d"] = b64_private = "AQ"
        parsed = parse_jwk(key, allow_private=True)
        self.assertEqual(parsed["d"], b64_private)

    def test_strip_private_material_is_recursive(self):
        key = rsa_key()
        key.update({"d": "AQ", "p": "AQ", "nested": {"q": "AQ", "k": "AA"}})
        stripped = strip_private_material(key)
        self.assertNotIn("d", stripped)
        self.assertNotIn("p", stripped)
        self.assertNotIn("q", stripped["nested"])
        self.assertNotIn("k", stripped["nested"])
        self.assertIn("d", key)

    def test_select_rsa_verification_key(self):
        key = rsa_key()
        selected = select_verification_key({"keys": [key]}, {"alg": "RS256", "kid": "rsa-test"}, allowed_algs=["RS256"])
        self.assertEqual(selected["kid"], "rsa-test")
        self.assertEqual(selected["kty"], "RSA")

    def test_select_hmac_key_preserves_shared_secret_for_verifier(self):
        key = oct_key()
        selected = select_verification_key({"keys": [key]}, {"alg": "HS256", "kid": "oct-test"}, allowed_algs=["HS256"])
        self.assertIn("k", selected)

    def test_hmac_asymmetric_confusion_is_blocked(self):
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [rsa_key()]}, {"alg": "HS256", "kid": "rsa-test"}, allowed_algs=["HS256"])
        self.assertEqual(caught.exception.code, "KEY_NOT_FOUND")

    def test_asymmetric_hmac_confusion_is_blocked(self):
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [oct_key()]}, {"alg": "RS256", "kid": "oct-test"}, allowed_algs=["RS256"])
        self.assertEqual(caught.exception.code, "KEY_NOT_FOUND")

    def test_inline_jwk_header_injection_is_blocked(self):
        report = audit_jwt_header({"alg": "RS256", "kid": "a", "jwk": rsa_key()})
        self.assertFalse(report.ok)
        self.assertIn("HEADER_FORBIDDEN", report.error_codes)

    def test_inline_x5c_header_injection_is_blocked(self):
        report = audit_jwt_header({"alg": "RS256", "kid": "a", "x5c": ["AAAA"]})
        self.assertFalse(report.ok)
        self.assertIn("HEADER_FORBIDDEN", report.error_codes)

    def test_remote_key_url_blocked_by_default_even_when_public(self):
        report = audit_jwt_header({"alg": "RS256", "kid": "a", "jku": "https://example.com/jwks.json"})
        self.assertFalse(report.ok)
        self.assertIn("REMOTE_KEY_REFERENCE", report.error_codes)

    def test_remote_key_url_public_https_passes_only_when_explicitly_enabled(self):
        report = audit_jwt_header(
            {"alg": "RS256", "kid": "a", "jku": "https://example.com/jwks.json"},
            allow_remote_key_urls=True,
        )
        self.assertTrue(report.ok, report.to_dict())

    def test_remote_key_url_private_ip_blocked_when_enabled(self):
        report = audit_jwt_header(
            {"alg": "RS256", "kid": "a", "jku": "https://127.0.0.1/jwks.json"},
            allow_remote_key_urls=True,
        )
        self.assertFalse(report.ok)
        self.assertIn("REMOTE_URL_UNSAFE", report.error_codes)

    def test_duplicate_kid_is_blocked(self):
        report = audit_jwks({"keys": [rsa_key("same"), rsa_key("same")]})
        self.assertFalse(report.ok)
        self.assertIn("KID_DUPLICATE", report.error_codes)

    def test_case_colliding_kid_is_blocked(self):
        report = audit_jwks({"keys": [rsa_key("KeyA"), rsa_key("keya")]})
        self.assertFalse(report.ok)
        self.assertIn("KID_COLLISION", report.error_codes)

    def test_alg_none_is_blocked(self):
        report = audit_jwt_header({"alg": "none", "kid": "a"})
        self.assertFalse(report.ok)
        self.assertIn("ALG_NONE", report.error_codes)

    def test_weak_rsa_is_blocked(self):
        report = audit_jwk(rsa_key(bit_length=1024))
        self.assertFalse(report.ok)
        self.assertIn("KEY_SIZE_WEAK", report.error_codes)

    def test_small_rsa_exponent_is_blocked(self):
        small = rsa_key(exponent="Aw")
        report = audit_jwk(small)
        self.assertFalse(report.ok)
        self.assertIn("KEY_SIZE_WEAK", report.error_codes)

    def test_wrong_ec_curve_algorithm_is_blocked(self):
        key = ec_key("P-256")
        key["alg"] = "ES384"
        report = audit_jwk(key)
        self.assertFalse(report.ok)
        self.assertIn("ALG_CONFUSION", report.error_codes)

    def test_use_mismatch_is_blocked(self):
        key = rsa_key()
        key["use"] = "enc"
        report = audit_jwk(key)
        self.assertFalse(report.ok)
        self.assertIn("USE_MISMATCH", report.error_codes)

    def test_key_ops_mismatch_is_blocked(self):
        key = rsa_key()
        key["key_ops"] = ["encrypt"]
        report = audit_jwk(key)
        self.assertFalse(report.ok)
        self.assertIn("KEY_OPS_MISMATCH", report.error_codes)

    def test_legacy_ipv4_obfuscation_decodes_loopback(self):
        self.assertEqual(str(parse_legacy_ipv4("2130706433")), "127.0.0.1")
        self.assertEqual(str(parse_legacy_ipv4("0177.0.0.1")), "127.0.0.1")
        self.assertEqual(str(parse_legacy_ipv4("0x7f000001")), "127.0.0.1")
        self.assertEqual(str(parse_legacy_ipv4("127.1")), "127.0.0.1")

    def test_https_url_accepts_public_name(self):
        self.assertIsNone(audit_https_url("https://example.com/jwks.json"))

    def test_strict_json_duplicate_members_rejected(self):
        with self.assertRaises(JwkCageError) as caught:
            parse_jwk('{"kty":"RSA","kty":"RSA"}', allow_private=True)
        self.assertEqual(caught.exception.code, "JSON_DUPLICATE_KEY")

    def test_report_json_contains_no_private_values(self):
        key = rsa_key()
        secret_value = "secret-bytes"
        key["d"] = secret_value
        report = audit_jwk(key)
        encoded = json.dumps(report.to_dict())
        self.assertNotIn(secret_value, encoded)


if __name__ == "__main__":
    unittest.main()
