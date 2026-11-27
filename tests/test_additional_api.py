from __future__ import annotations

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
from pyjwkcage.netguard import audit_https_url

from helpers import b64u, ec_key, oct_key, okp_key, rsa_key, rsa_modulus_bytes


class TestAdditionalApiBehavior(unittest.TestCase):
    def test_parse_jwk_returns_detached_copy(self):
        key = rsa_key()
        parsed = parse_jwk(key)
        parsed["kid"] = "changed"
        self.assertEqual(key["kid"], "rsa-test")

    def test_multiple_missing_kids_are_ambiguous_in_jwks(self):
        first = rsa_key("x")
        second = rsa_key("y")
        first.pop("kid")
        second.pop("kid")
        report = audit_jwks({"keys": [first, second]})
        self.assertIn("KID_REQUIRED", report.error_codes)

    def test_select_requires_kid_by_default(self):
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [rsa_key()]}, {"alg": "RS256"}, allowed_algs=["RS256"])
        self.assertEqual(caught.exception.code, "KID_REQUIRED")

    def test_select_without_kid_rejects_multiple_candidates(self):
        first = rsa_key("one")
        second = rsa_key("two")
        first_raw = bytearray(rsa_modulus_bytes())
        second_raw = bytearray(rsa_modulus_bytes())
        first_raw[10] = 21
        second_raw[10] = 22
        first["n"] = b64u(bytes(first_raw))
        second["n"] = b64u(bytes(second_raw))
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [first, second]}, {"alg": "RS256"}, allowed_algs=["RS256"], require_kid=False)
        self.assertEqual(caught.exception.code, "KEY_AMBIGUOUS")

    def test_select_rejects_algorithm_outside_caller_allowlist(self):
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [rsa_key()]}, {"alg": "RS256", "kid": "rsa-test"}, allowed_algs=["RS384"])
        self.assertEqual(caught.exception.code, "ALG_NOT_ALLOWED")

    def test_select_rejects_in_key_algorithm_mismatch(self):
        key = rsa_key()
        key["alg"] = "RS384"
        with self.assertRaises(JwkCageError) as caught:
            select_verification_key({"keys": [key]}, {"alg": "RS256", "kid": "rsa-test"}, allowed_algs=["RS256", "RS384"])
        self.assertEqual(caught.exception.code, "KEY_NOT_FOUND")

    def test_key_ops_verify_is_accepted_for_verification_key(self):
        key = rsa_key()
        key["key_ops"] = ["verify"]
        self.assertTrue(audit_jwk(key).ok)

    def test_p384_valid_key_is_accepted(self):
        self.assertTrue(audit_jwk(ec_key("P-384")).ok)

    def test_p521_valid_key_is_accepted(self):
        self.assertTrue(audit_jwk(ec_key("P-521")).ok)

    def test_select_es384_uses_exact_p384_curve(self):
        key = ec_key("P-384", "ec-384")
        selected = select_verification_key({"keys": [key]}, {"alg": "ES384", "kid": "ec-384"}, allowed_algs=["ES384"])
        self.assertEqual(selected["crv"], "P-384")

    def test_select_eddsa_key(self):
        key = okp_key()
        selected = select_verification_key({"keys": [key]}, {"alg": "EdDSA", "kid": "okp-test"}, allowed_algs=["EdDSA"])
        self.assertEqual(selected["crv"], "Ed25519")

    def test_thumbprint_ignores_non_required_members(self):
        key = rsa_key()
        first = compute_jwk_thumbprint(key)
        clone = dict(key)
        clone["kid"] = "different"
        clone["use"] = "sig"
        self.assertEqual(compute_jwk_thumbprint(clone), first)

    def test_strip_private_does_not_mutate_input(self):
        key = rsa_key()
        key["d"] = "AQ"
        strip_private_material(key)
        self.assertIn("d", key)

    def test_valid_jwe_header_is_accepted(self):
        report = audit_jwt_header({"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "enc-key"})
        self.assertTrue(report.ok, report.to_dict())

    def test_unknown_jwe_enc_is_rejected(self):
        report = audit_jwt_header({"alg": "RSA-OAEP-256", "enc": "A256CBC", "kid": "enc-key"})
        self.assertIn("ALG_UNSUPPORTED", report.error_codes)

    def test_invalid_epk_is_rejected(self):
        report = audit_jwt_header({"alg": "ECDH-ES", "enc": "A256GCM", "epk": {"kty": "EC", "crv": "P-224"}})
        self.assertIn("HEADER_INVALID", report.error_codes)

    def test_p2c_lower_bound_enforced(self):
        report = audit_jwt_header({"alg": "PBES2-HS256+A128KW", "enc": "A128GCM", "p2c": 999, "p2s": "AA"})
        self.assertIn("HEADER_INVALID", report.error_codes)

    def test_metadata_google_remote_url_blocked(self):
        self.assertIsNotNone(audit_https_url("https://metadata.google.internal/computeMetadata/v1/"))

    def test_metadata_ip_remote_url_blocked(self):
        self.assertIsNotNone(audit_https_url("https://169.254.169.254/latest/meta-data/"))

    def test_alibaba_metadata_remote_url_blocked(self):
        self.assertIsNotNone(audit_https_url("https://100.100.100.200/latest/meta-data/"))

    def test_azure_metadata_remote_url_blocked(self):
        self.assertIsNotNone(audit_https_url("https://168.63.129.16/metadata/instance"))

    def test_aws_ipv6_metadata_remote_url_blocked(self):
        self.assertIsNotNone(audit_https_url("https://[fd00:ec2::254]/latest/meta-data/"))

    def test_parse_oct_key_requires_allow_private(self):
        key = oct_key()
        with self.assertRaises(JwkCageError):
            parse_jwk(key)
        parsed = parse_jwk(key, allow_private=True)
        self.assertEqual(parsed["kty"], "oct")

    def test_public_oct_key_is_flagged_as_secret_material(self):
        report = audit_jwk(oct_key())
        self.assertIn("PRIVATE_MATERIAL", report.error_codes)

    def test_short_hmac_key_is_not_selected_for_hs256(self):
        key = oct_key(size=16)
        jwks_report = audit_jwks({"keys": [key]}, public=False)
        self.assertIn("KEY_SIZE_WEAK", jwks_report.error_codes)
        with self.assertRaises(JwkCageError):
            select_verification_key({"keys": [key]}, {"alg": "HS256", "kid": "oct-test"}, allowed_algs=["HS256"])

    def test_hs384_key_with_48_bytes_is_selected(self):
        key = oct_key(size=48, alg="HS384")
        selected = select_verification_key({"keys": [key]}, {"alg": "HS384", "kid": "oct-test"}, allowed_algs=["HS384"])
        self.assertIn("k", selected)

    def test_noncanonical_base64url_is_rejected(self):
        key = rsa_key()
        key["n"] = key["n"] + "=="
        self.assertIn("BASE64URL_INVALID", audit_jwk(key).error_codes)

    def test_duplicate_json_members_reject_jwks(self):
        text = '{"keys":[],"keys":[]}'
        report = audit_jwks(text)
        self.assertIn("JSON_DUPLICATE_KEY", report.error_codes)

    def test_wrong_certificate_thumbprint_length_rejected(self):
        key = rsa_key()
        key["x5t#S256"] = b64u(b"short")
        self.assertIn("KEY_PARAMETER_INVALID", audit_jwk(key).error_codes)

    def test_bad_x5c_parameter_rejected(self):
        key = rsa_key()
        key["x5c"] = ["not canonical!"]
        self.assertIn("KEY_PARAMETER_INVALID", audit_jwk(key).error_codes)

    def test_private_material_does_not_leak_into_exception_text(self):
        key = rsa_key()
        secret = "very-secret-value"
        key["d"] = secret
        try:
            parse_jwk(key)
        except JwkCageError as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail("private key material was accepted")

    def test_audit_report_is_json_serializable(self):
        report = audit_jwks({"keys": [rsa_key()]})
        json.dumps(report.to_dict())

    def test_hmac_thumbprint_is_refused(self):
        with self.assertRaises(JwkCageError) as caught:
            compute_jwk_thumbprint(oct_key())
        self.assertEqual(caught.exception.code, "THUMBPRINT_INVALID")


if __name__ == "__main__":
    unittest.main()
