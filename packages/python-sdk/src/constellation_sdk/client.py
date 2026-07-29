"""Dependency-free client for Constellation HTTP and SSE contracts."""

from __future__ import annotations

import json
from collections.abc import Generator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class Response(Protocol):
    """The small response surface needed by the client."""

    status: int

    def read(self, size: int = -1) -> bytes: ...
    def __enter__(self) -> Response: ...
    def __exit__(self, *args: object) -> None: ...


class Opener(Protocol):
    """Injectable transport used by tests and restricted applications."""

    def __call__(self, request: Request, timeout: float) -> Response: ...


@dataclass(slots=True)
class ConstellationError(Exception):
    """Normalized Constellation API failure."""

    message: str
    status: int
    code: str | None = None
    trace_id: str | None = None

    def __str__(self) -> str:
        return self.message


class ConstellationClient:
    """Synchronous client for OpenAI-compatible and native APIs."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:4317",
        api_key: str | None = None,
        timeout: float = 60.0,
        opener: Opener = urlopen,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._opener = opener

    def models(self) -> dict[str, Any]:
        return self._request("GET", "/v1/models")

    def chat_completions(self, **request: Any) -> dict[str, Any]:
        return self._request(
            "POST", "/v1/chat/completions", {**request, "stream": False}
        )

    def responses(self, **request: Any) -> dict[str, Any]:
        return self._request("POST", "/v1/responses", request)

    def embeddings(self, **request: Any) -> dict[str, Any]:
        return self._request("POST", "/v1/embeddings", request)

    def cluster(self) -> dict[str, Any]:
        return self._request("GET", "/constellation/v1/cluster")

    def devices(self) -> list[dict[str, Any]]:
        value = self._request("GET", "/constellation/v1/devices")
        if not isinstance(value, list):
            raise ConstellationError("invalid devices response", 502, "invalid_response")
        return value

    def events(self, *, after: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        query = urlencode({"after": after, "limit": limit})
        value = self._request("GET", f"/constellation/v1/events?{query}")
        if not isinstance(value, list):
            raise ConstellationError("invalid events response", 502, "invalid_response")
        return value

    def stream_chat(self, **request: Any) -> Generator[dict[str, Any], None, None]:
        """Yields decoded chat completion SSE chunks until the DONE sentinel."""

        response = self._open(
            "POST", "/v1/chat/completions", {**request, "stream": True}
        )
        with response:
            buffer = b""
            while chunk := response.read(8192):
                buffer += chunk.replace(b"\r\n", b"\n")
                while b"\n\n" in buffer:
                    frame, buffer = buffer.split(b"\n\n", 1)
                    for line in frame.splitlines():
                        if not line.startswith(b"data: "):
                            continue
                        payload = line[6:]
                        if payload == b"[DONE]":
                            return
                        value = json.loads(payload)
                        if not isinstance(value, dict):
                            raise ConstellationError(
                                "invalid streaming response", 502, "invalid_response"
                            )
                        yield value

    def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
    ) -> Any:
        response = self._open(method, path, body)
        with response:
            try:
                return json.loads(response.read())
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ConstellationError(
                    "invalid JSON response", response.status, "invalid_response"
                ) from error

    def _open(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
    ) -> Response:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        encoded = None if body is None else json.dumps(body).encode()
        request = Request(
            f"{self.base_url}{path}", data=encoded, headers=headers, method=method
        )
        try:
            return self._opener(request, self._timeout)
        except HTTPError as error:
            raw = error.read()
            message = f"Constellation request failed ({error.code})"
            code = None
            trace_id = error.headers.get("x-trace-id")
            try:
                value = json.loads(raw)
                details = value.get("error", {})
                message = details.get("message", message)
                code = details.get("code")
                trace_id = details.get("trace_id", trace_id)
            except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                pass
            raise ConstellationError(message, error.code, code, trace_id) from error
