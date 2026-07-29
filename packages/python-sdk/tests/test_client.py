"""Contract tests for the dependency-free Python client."""

from __future__ import annotations

import io
import json
import unittest
from typing import Self
from urllib.error import HTTPError
from urllib.request import Request

from constellation_sdk import ConstellationClient, ConstellationError


class FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class ClientTests(unittest.TestCase):
    def test_bearer_authentication_and_models(self) -> None:
        observed: list[Request] = []

        def opener(request: Request, timeout: float) -> FakeResponse:
            self.assertEqual(timeout, 4.0)
            observed.append(request)
            return FakeResponse(json.dumps({"object": "list", "data": []}).encode())

        client = ConstellationClient(api_key="test-key", timeout=4.0, opener=opener)
        self.assertEqual(client.models()["object"], "list")
        self.assertEqual(observed[0].get_header("Authorization"), "Bearer test-key")

    def test_normalized_error(self) -> None:
        def opener(_request: Request, _timeout: float) -> FakeResponse:
            body = io.BytesIO(
                json.dumps(
                    {"error": {"message": "denied", "code": "forbidden", "trace_id": "t1"}}
                ).encode()
            )
            raise HTTPError("http://local", 403, "Forbidden", {}, body)

        with self.assertRaises(ConstellationError) as raised:
            ConstellationClient(opener=opener).models()
        self.assertEqual(raised.exception.code, "forbidden")
        self.assertEqual(raised.exception.trace_id, "t1")

    def test_sse_stream(self) -> None:
        payload = b'data: {"id":"one"}\n\ndata: {"id":"two"}\n\ndata: [DONE]\n\n'

        def opener(_request: Request, _timeout: float) -> FakeResponse:
            return FakeResponse(payload)

        chunks = list(ConstellationClient(opener=opener).stream_chat(model="mock"))
        self.assertEqual([chunk["id"] for chunk in chunks], ["one", "two"])


if __name__ == "__main__":
    unittest.main()
