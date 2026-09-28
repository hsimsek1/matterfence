"""Standalone synthetic SQLite search target; run from a repository checkout."""

import argparse
import json
import re
import sqlite3
import sys
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "matterfence/core/mf_auth_001.json"
RESULT_LIMIT = 5
MAX_REQUEST_BYTES = 64 * 1024


def build_store(fixture: dict) -> sqlite3.Connection:
    """Index a trusted synthetic fixture and snapshot its per-document grants."""
    # HTTPServer handles one request at a time, sometimes on a test-owned thread.
    store = sqlite3.connect(":memory:", check_same_thread=False)
    try:
        store.executescript("""
            CREATE TABLE users (id TEXT PRIMARY KEY);
            CREATE TABLE grants (
                user_id TEXT, document_id TEXT, PRIMARY KEY (user_id, document_id)
            );
            CREATE VIRTUAL TABLE documents USING fts5(
                document_id UNINDEXED, title, content, tokenize='porter unicode61'
            );
        """)
        store.executemany(
            "INSERT INTO users VALUES (?)", [(user["id"],) for user in fixture["users"]]
        )
        for matter in fixture["matters"]:
            allowed = set(matter["authorized_user_ids"]) - set(
                matter.get("screened_user_ids", [])
            )
            for document in matter["documents"]:
                store.execute(
                    "INSERT INTO documents VALUES (?, ?, ?)",
                    (document["id"], document["title"], document["content"]),
                )
                readers = allowed
                if document.get("is_privileged", False):
                    readers = allowed & set(matter.get("privileged_user_ids", []))
                store.executemany(
                    "INSERT INTO grants VALUES (?, ?)",
                    [(user_id, document["id"]) for user_id in sorted(readers)],
                )
        store.commit()
    except Exception:
        store.close()
        raise
    return store


def retrieve(
    store: sqlite3.Connection, user_id: str, prompt: str, mode: str = "secure"
) -> dict:
    """Search by literal terms; return only the selected rows' text and IDs."""
    if mode not in {"secure", "vulnerable"}:
        raise ValueError("Unknown mode.")
    if not store.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
        raise PermissionError("Unknown synthetic user.")
    # Quote individual English-demo tokens so prompts cannot supply FTS operators.
    terms = sorted(set(re.findall(r"[a-z0-9]+", prompt.lower())))
    if len(terms) > 64:
        raise ValueError("Use at most 64 distinct search terms.")
    rows = []
    if terms:
        query = " OR ".join(f'"{term}"' for term in terms)
        rows = store.execute(
            """SELECT document_id, content FROM documents
               WHERE documents MATCH ?
                 AND (? = 'vulnerable' OR document_id IN (
                     SELECT document_id FROM grants WHERE user_id = ?
                 ))
               ORDER BY rank, document_id LIMIT ?""",
            (query, mode, user_id, RESULT_LIMIT),
        ).fetchall()
    # This is the answering boundary: every included body has a corresponding ID.
    return {
        "response_text": "\n".join(content for _, content in rows),
        "retrieved_document_ids": [document_id for document_id, _ in rows],
        "error": None,
    }


def create_server(
    store: sqlite3.Connection, mode: str = "secure", port: int = 0
) -> HTTPServer:
    """Bind loopback; the caller starts the server and closes it and the store."""
    if mode not in {"secure", "vulnerable"}:
        raise ValueError("Unknown mode.")

    class Handler(BaseHTTPRequestHandler):
        timeout = 5

        def do_GET(self) -> None:
            if self.path not in {"/", "/retrieve"}:
                self._error(404, "Unknown endpoint.")
                return
            self._reply(200, {
                "message": "Synthetic SQLite search. POST user_id and prompt to /retrieve.",
                "mode": mode,
            })

        def do_POST(self) -> None:
            if self.path != "/retrieve":
                self._error(404, "Unknown endpoint.")
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (
                self.headers.get_all("Transfer-Encoding")
                or self.headers.get_all("Content-Encoding")
                or self.headers.get_content_type() != "application/json"
                or len(lengths) != 1
                or not lengths[0].isascii()
                or not lengths[0].isdigit()
                or len(lengths[0]) > 6
            ):
                self._error(400, "Send length-delimited, uncompressed JSON.")
                return
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._error(413, "Request size is outside the demo limit.")
                return
            try:
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("Incomplete request.")
                request = json.loads(body)
                if (
                    not isinstance(request, dict)
                    or set(request) != {"user_id", "prompt"}
                    or any(not isinstance(value, str) for value in request.values())
                    or any(not value.strip() for value in request.values())
                ):
                    raise ValueError("Invalid request.")
                result = retrieve(store, request["user_id"], request["prompt"], mode)
            except PermissionError:
                self._error(403, "Unknown synthetic user.")
                return
            except (ValueError, TimeoutError):
                self._error(400, "Invalid request.")
                return
            except sqlite3.Error:
                self._error(500, "Search failed.")
                return
            self._reply(200, result)

        def _error(self, status: int, message: str) -> None:
            self._reply(status, {
                "response_text": "", "retrieved_document_ids": None, "error": message,
            })

        def _reply(self, status: int, result: dict) -> None:
            body = json.dumps(result).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            try:
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass  # The requesting client may already have disconnected.

        def log_message(self, format: str, *args) -> None:
            pass  # Keep prompts, IDs, and untrusted paths out of access logs.

    return HTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    """Load the bundled fixture and serve until Ctrl+C; secure mode is default."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("secure", "vulnerable"), default="secure")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("Port must be between 0 and 65535.")
    try:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with (
            closing(build_store(fixture)) as store,
            create_server(store, args.mode, args.port) as server,
        ):
            print(f"http://127.0.0.1:{server.server_port}/retrieve", flush=True)
            print(
                f"Synthetic SQLite example: {args.mode} mode; no authentication or LLM.",
                file=sys.stderr,
            )
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, sqlite3.Error):
        parser.exit(2, "Unable to start: check port, bundled fixture, and SQLite FTS5.\n")


if __name__ == "__main__":
    main()
