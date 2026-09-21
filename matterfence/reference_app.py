"""A loopback-only synthetic retrieval example, not a production AI service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Annotated

import typer
from pydantic import BaseModel, ConfigDict

from matterfence.core.scenario import NonEmptyText, load_auth_scenario
from matterfence.synthetic_firm.models import Matter, User
from matterfence.targets.mock import TargetResult

MAX_REQUEST_BYTES = 64 * 1024
app = typer.Typer(add_completion=False)


class RetrievalRequest(BaseModel):
    """Query input only: clients cannot supply documents or permission lists."""

    model_config = ConfigDict(extra="forbid", strict=True)

    user_id: NonEmptyText
    prompt: NonEmptyText


def retrieve_documents(
    request: RetrievalRequest, users: list[User], matters: list[Matter]
) -> TargetResult:
    """Return all readable records; the prompt does not rank or filter results."""
    user_id = request.user_id
    if not any(user.id == user_id for user in users):
        raise PermissionError("Unknown synthetic user.")

    documents = []
    for matter in matters:
        # Check the application's own policy before reading document content.
        if (
            user_id not in matter.authorized_user_ids
            or user_id in matter.screened_user_ids
        ):
            continue
        for document in matter.documents:
            if document.is_privileged and user_id not in matter.privileged_user_ids:
                continue
            documents.append(document)

    return TargetResult(
        response_text="\n".join(document.content for document in documents),
        retrieved_document_ids=[document.id for document in documents],
    )


def create_server(
    users: list[User], matters: list[Matter], port: int = 8000
) -> ThreadingHTTPServer:
    """Bind a local server to a preloaded store; the caller starts and closes it."""
    page = files("matterfence").joinpath("reference_app.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        # StreamRequestHandler applies this before reading headers or the body.
        timeout = 5

        def do_GET(self) -> None:
            if self.path not in {"/", "/retrieve"}:
                self._error(404, "Unknown endpoint.")
                return
            self._send(200, page, "text/html; charset=utf-8")

        def do_POST(self) -> None:
            if self.path != "/retrieve":
                self._error(404, "Unknown endpoint.")
                return
            if self.headers.get_all("Transfer-Encoding"):
                self._error(400, "Transfer encoding is not supported.")
                return
            encodings = self.headers.get_all("Content-Encoding", [])
            if (
                self.headers.get_content_type() != "application/json"
                or len(encodings) > 1
                or (
                    encodings
                    and encodings[0].strip().lower() not in {"", "identity"}
                )
            ):
                self._error(415, "Send an uncompressed JSON request.")
                return
            lengths = self.headers.get_all("Content-Length", [])
            try:
                if (
                    len(lengths) != 1
                    or not lengths[0].isascii()
                    or not lengths[0].isdigit()
                ):
                    raise ValueError("Invalid content length.")
                length = int(lengths[0])
                if length < 1:
                    raise ValueError("Empty request.")
                if length > MAX_REQUEST_BYTES:
                    self._error(413, "Request is too large.")
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("Incomplete request.")
                request = RetrievalRequest.model_validate_json(body)
            except (ValueError, TimeoutError):
                self._error(400, "Invalid request.")
                return

            try:
                result = retrieve_documents(request, users, matters)
            except PermissionError:
                self._error(403, "Unknown synthetic user.")
                return
            self._reply(200, result)

        def _error(self, status: int, message: str) -> None:
            self._reply(status, TargetResult(response_text="", error=message))

        def _reply(self, status: int, result: TargetResult) -> None:
            body = result.model_dump_json().encode("utf-8")
            self._send(status, body, "application/json")

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            try:
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                # A client can disconnect while the safe response is written.
                pass

        def log_message(self, format: str, *args) -> None:
            # Do not log untrusted request paths or other request data.
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


@app.command()
def serve(
    port: Annotated[
        int,
        typer.Option(
            min=0, max=65535, help="Local port; 0 chooses an available port."
        ),
    ] = 8000,
) -> None:
    """Serve the bundled synthetic fixture on loopback only. Stop with Ctrl+C."""
    try:
        scenario = load_auth_scenario()
        with create_server(scenario.users, scenario.matters, port) as server:
            print(f"http://127.0.0.1:{server.server_port}/retrieve", flush=True)
            typer.echo(
                "Synthetic reference app only; no authentication or LLM.", err=True
            )
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError):
        typer.echo(
            "Unable to start reference app: check the port and fixture.", err=True
        )
        raise typer.Exit(code=2) from None


if __name__ == "__main__":
    app()
