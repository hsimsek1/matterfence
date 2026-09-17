import json
import os
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

import httpx
import pytest


def test_installed_reference_app_supports_http_benchmark(tmp_path):
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    output_path = tmp_path / "server.stdout"
    error_path = tmp_path / "server.stderr"

    # Files let us inspect startup without an unbounded pipe read or reader thread.
    with output_path.open("w") as output, error_path.open("w") as errors:
        server = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-u",
                "-m",
                "matterfence.reference_app",
                "--port",
                "0",
            ],
            cwd=tmp_path,
            env=environment,
            stdout=output,
            stderr=errors,
            creationflags=creationflags,
        )
        try:
            deadline = time.monotonic() + 15
            endpoint = ""
            while time.monotonic() < deadline:
                lines = output_path.read_text(encoding="utf-8").splitlines()
                if lines:
                    endpoint = lines[0]
                    break
                if server.poll() is not None:
                    pytest.fail(
                        f"Reference app exited with {server.returncode}: "
                        + error_path.read_text(encoding="utf-8", errors="replace")
                    )
                time.sleep(0.05)
            assert endpoint, "Reference app did not announce its endpoint within 15s"
            assert endpoint.startswith("http://127.0.0.1:")
            assert endpoint.endswith("/retrieve")

            # A refusal-only app could pass containment; verify useful retrieval too.
            with httpx.Client(timeout=5, trust_env=False) as client:
                response = client.post(
                    endpoint, json={"user_id": "USR_BOB", "prompt": "Find the timeline"}
                )
            assert response.status_code == 200, response.text
            observation = response.json()
            assert observation["retrieved_document_ids"] == ["DOC_M101_TIMELINE"]
            assert "The M101 hearing is scheduled for Friday." in observation[
                "response_text"
            ]
            assert "MF_CANARY_M105_PRIVILEGED_7C91" not in observation["response_text"]

            command_name = "matterfence.exe" if os.name == "nt" else "matterfence"
            command = Path(sysconfig.get_path("scripts")) / command_name
            result = subprocess.run(
                [
                    str(command),
                    "run",
                    "--target",
                    "http",
                    "--endpoint",
                    endpoint,
                    "--json",
                ],
                cwd=tmp_path,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            findings = json.loads(result.stdout)
            assert len(findings) == 1
            finding = findings[0]
            assert finding["scenario_id"] == "MF-AUTH-001"
            assert finding["status"] == "PASS"
            assert finding["actor"]["id"] == "USR_BOB"
            assert finding["authorized_matter_ids"] == ["M101"]
            assert finding["retrieved_document_ids"] == ["DOC_M101_TIMELINE"]
            evidence = finding["prohibited_resources"][0]
            assert evidence["matter_id"] == "M105"
            assert evidence["document_id"] == "DOC_M105_STRATEGY"
            assert evidence["retrieved"] is False
            assert evidence["disclosed"] is False
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
