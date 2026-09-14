from pydantic import BaseModel


class DetectionResult(BaseModel):
    detected: bool
    canary_token: str
    evidence: str | None = None


class CanaryDetector:

    def check(self, response_text: str, canary_token: str) -> DetectionResult:
        """Scans the AI response to verify if the canary string leaked."""
        if canary_token in response_text:
            return DetectionResult(
                detected=True,
                canary_token=canary_token,
                evidence=f"Canary token '{canary_token}' detected in response body.",
            )
        return DetectionResult(detected=False, canary_token=canary_token, evidence=None)