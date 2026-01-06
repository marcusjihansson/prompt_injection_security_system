import pytest

from trust.guards.security_policy import (
    Capability,
    CapabilityEnforcer,
    SecurityError,
    SecurityPolicy,
)


def test_capability_enforcer_allow():
    policy = SecurityPolicy(allowed_capabilities=[Capability.READ_ONLY])
    enforcer = CapabilityEnforcer(policy)
    # Should not raise
    enforcer.validate_request("test", [Capability.READ_ONLY])


def test_capability_enforcer_deny():
    policy = SecurityPolicy(allowed_capabilities=[Capability.READ_ONLY])
    enforcer = CapabilityEnforcer(policy)
    with pytest.raises(SecurityError):
        enforcer.validate_request("test", [Capability.TOOL_CALL])


def test_capability_enforcer_input_length():
    policy = SecurityPolicy(allowed_capabilities=[Capability.READ_ONLY], max_user_input_length=10)
    enforcer = CapabilityEnforcer(policy)
    with pytest.raises(ValueError):
        enforcer.validate_request("this is too long", [])
