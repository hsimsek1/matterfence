from matterfence.core.runner import TestStatus, run_mf_matter_001
from matterfence.detectors.canary import CanaryDetector
from matterfence.synthetic_firm.models import Matter
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget


def test_matter_authorization_logic():
    matter = Matter(
        id="M101",
        title="Test Case",
        client_name="Test Client",
        authorized_user_ids=["USER_ALICE"],
        canary_token="SECRET_123",
    )
    assert matter.is_user_authorized("USER_ALICE") is True
    assert matter.is_user_authorized("USER_BOB") is False


def test_canary_detector_finds_token():
    detector = CanaryDetector()
    result = detector.check("Here is the secret: MF_CANARY_TEST", "MF_CANARY_TEST")
    assert result.detected is True
    assert "MF_CANARY_TEST" in (result.evidence or "")


def test_canary_detector_passes_clean_text():
    detector = CanaryDetector()
    result = detector.check("Access denied to requested records.", "MF_CANARY_TEST")
    assert result.detected is False
    assert result.evidence is None


def test_vulnerable_target_fails_security_scan():
    target = VulnerableMockTarget()
    result = run_mf_matter_001(target)
    assert result.status == TestStatus.FAIL
    assert result.evidence is not None


def test_secure_target_passes_security_scan():
    target = SecureMockTarget()
    result = run_mf_matter_001(target)
    assert result.status == TestStatus.PASS
    assert result.evidence is None