from matterfence.core.runner import TestStatus, run_mf_wall_001
from matterfence.synthetic_firm.models import Matter
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget


def test_ethical_wall_authorization():
    matter = Matter(
        id="M103",
        title="Atlas Investigation",
        client_name="Atlas Capital",
        authorized_user_ids=["USR_ALICE", "USR_DANIEL"],
        screened_user_ids=["USR_DANIEL"],
        canary_token="MF_CANARY_TEST",
    )
    # Alice is authorized and not screened
    assert matter.is_user_authorized("USR_ALICE") is True
    # Daniel is authorized BUT screened, so he must be blocked
    assert matter.is_user_authorized("USR_DANIEL") is False


def test_vulnerable_target_fails_wall_test():
    target = VulnerableMockTarget()
    result = run_mf_wall_001(target)
    assert result.status == TestStatus.FAIL
    assert result.evidence is not None


def test_secure_target_passes_wall_test():
    target = SecureMockTarget()
    result = run_mf_wall_001(target)
    assert result.status == TestStatus.PASS
    assert result.evidence is None