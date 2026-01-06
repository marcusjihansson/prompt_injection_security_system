import pytest

from trust.guards.primitives import SecureField, TrustLevel


def test_trust_level_comparisons():
    assert TrustLevel.USER > TrustLevel.SYSTEM  # USER=2 > SYSTEM=0
    assert TrustLevel.VERIFIED > TrustLevel.SYSTEM  # VERIFIED=1 > SYSTEM=0
    assert TrustLevel.DERIVED > TrustLevel.USER  # DERIVED=3 > USER=2
    assert TrustLevel.SYSTEM == TrustLevel.SYSTEM


def test_secure_field_validation():
    field = SecureField("test", TrustLevel.USER, required=True)
    assert field.validate("value") == True
    assert field.validate(None) == False

    field_optional = SecureField("test", TrustLevel.USER, required=False)
    assert field_optional.validate(None) == True


def test_secure_field_sanitize():
    field = SecureField("test", TrustLevel.USER, sanitize=True)
    assert field.sanitize == True

    field_no_sanitize = SecureField("test", TrustLevel.SYSTEM, sanitize=False)
    assert field_no_sanitize.sanitize == False
