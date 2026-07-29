"""Live compatibility checks using the official OpenAI Python client."""

from __future__ import annotations

import os

from openai import OpenAI


def main() -> None:
    base = os.environ["CONSTELLATION_COMPAT_URL"]
    client = OpenAI(
        api_key=os.environ.get("CONSTELLATION_COMPAT_KEY", "local-test-key"),
        base_url=f"{base}/v1",
        max_retries=0,
    )
    models = client.models.list()
    assert any(model.id == "constellation/mock" for model in models.data)
    completion = client.chat.completions.create(
        model="constellation/mock",
        messages=[{"role": "user", "content": "official Python client"}],
    )
    assert "official Python client" in (completion.choices[0].message.content or "")
    chunks = client.chat.completions.create(
        model="constellation/mock",
        messages=[{"role": "user", "content": "Python stream contract"}],
        stream=True,
    )
    streamed = "".join(chunk.choices[0].delta.content or "" for chunk in chunks)
    assert "Python stream contract" in streamed
    response = client.responses.create(model="constellation/mock", input="responses contract")
    assert response.object == "response"


if __name__ == "__main__":
    main()
