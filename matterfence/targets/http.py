"""Observed retrieval from an explicitly configured, local test application."""

import httpx

from matterfence.synthetic_firm.models import Document, Matter, User
from matterfence.targets.mock import BaseLegalTarget, TargetResult

TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1024 * 1024


class HttpLegalTarget(BaseLegalTarget):
    """Connect MF-AUTH-001 to a loopback HTTP endpoint with preloaded test data."""

    def __init__(self, endpoint: str) -> None:
        try:
            url = httpx.URL(endpoint)
        except httpx.InvalidURL:
            raise ValueError("Invalid local HTTP endpoint.") from None
        if (
            url.scheme != "http"
            or url.host not in {"127.0.0.1", "::1"}
            or url.userinfo
            or url.query
            or url.fragment
        ):
            raise ValueError("Use a loopback HTTP URL without credentials or queries.")
        self.endpoint = url

    def retrieve(self, user: User, matters: list[Matter], prompt: str) -> TargetResult:
        """Send only actor ID and prompt; return validated retrieval observations.

        The external application's test store must already contain the fixture.
        `matters` is deliberately unused: evaluation policy is not query input.
        Transport and validation errors propagate to the runner's safe ERROR path.
        """
        with httpx.stream(
            "POST",
            self.endpoint,
            json={"user_id": user.id, "prompt": prompt},
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        ) as response:
            response.raise_for_status()
            # Reject compression before HTTPX can expand an untrusted response.
            encoding = response.headers.get("Content-Encoding", "").strip().lower()
            if encoding not in {"", "identity"}:
                raise ValueError("Compressed target responses are not supported.")
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=8192):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Target response exceeds the local size limit.")
        return TargetResult.model_validate_json(bytes(body))

    def query_matter(self, user: User, matter: Matter, prompt: str) -> str:
        raise NotImplementedError("The HTTP target supports observed retrieval only.")

    def summarize_document(
        self, user: User, document: Document, internal_matter: Matter
    ) -> str:
        raise NotImplementedError("The HTTP target supports observed retrieval only.")
