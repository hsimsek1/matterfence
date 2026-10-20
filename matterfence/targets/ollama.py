"""Optional, fixed-loopback client for the small Qwen3 exhibit pilot."""

import json
from time import perf_counter

import httpx

MODEL = "qwen3:1.7b"
OPTIONS = {
    "temperature": 0,
    "seed": 42,
    "num_ctx": 4096,
    "num_predict": 256,
    "num_thread": 4,
    "num_gpu": 0,
}
MAX_RESPONSE_BYTES = 1024 * 1024


class OllamaClient:
    """Send only to local Ollama; callers own and close this client's connection."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self.http = httpx.Client(
            base_url="http://127.0.0.1:11434",
            transport=transport,
            timeout=httpx.Timeout(180, connect=5),
            trust_env=False,
            follow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        )
        self.calls: list[dict] = []

    def close(self) -> None:
        """Release HTTP connections; this does not stop the user's Ollama service."""
        self.http.close()

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        """Return bounded JSON, retaining request/reply evidence even on failure."""
        event = {"path": path, "request": payload}
        self.calls.append(event)
        started = perf_counter()
        try:
            with self.http.stream(method, path, json=payload) as response:
                event["http_status"] = response.status_code
                response.raise_for_status()
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("Compressed Ollama replies are not supported")
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise ValueError("Ollama reply exceeds the evidence size limit")
                event["raw_response"] = body.decode("utf-8")
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise TypeError("Ollama must return a JSON object")
                return result
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            event["error"] = type(exc).__name__
            raise
        finally:
            event["elapsed_seconds"] = round(perf_counter() - started, 4)

    def identity(self) -> dict:
        """Return runtime version and the installed model's full content digest."""
        version = self._request("GET", "/api/version").get("version")
        models = self._request("GET", "/api/tags").get("models")
        if not isinstance(version, str) or not version or not isinstance(models, list):
            raise ValueError("Missing Ollama identity")
        matches = [
            item
            for item in models
            if isinstance(item, dict) and item.get("name") == MODEL
        ]
        if len(matches) != 1:
            raise ValueError(f"Install {MODEL} locally before running the pilot")
        digest = matches[0].get("digest")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("Missing model digest")
        return {"ollama_version": version, "model": MODEL, "digest": digest}

    def chat(self, messages: list[dict], *, schema: dict | None = None) -> str:
        """Take role/content messages; return a complete assistant answer or raise."""
        payload = {
            "model": MODEL,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": dict(OPTIONS),
            "keep_alive": 0,
        }
        if schema is not None:
            payload["format"] = schema
        result = self._request("POST", "/api/chat", payload)
        message = result.get("message")
        if (
            result.get("done") is not True
            or result.get("done_reason") != "stop"
            or not isinstance(message, dict)
            or message.get("role") != "assistant"
            or not isinstance(message.get("content"), str)
            or not message["content"].strip()
            or message.get("tool_calls")
        ):
            self.calls[-1]["error"] = "InvalidChatResponse"
            raise ValueError("Incomplete or unsupported Ollama answer")
        return message["content"]
