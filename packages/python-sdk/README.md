# Constellation Python SDK

The Python 3.13 SDK exposes Constellation's OpenAI-compatible HTTP surface,
native cluster inventory, durable events, and streaming chat without runtime
dependencies.

```python
from constellation_sdk import ConstellationClient

client = ConstellationClient(api_key="local-key")
for chunk in client.stream_chat(
    model="mock-deterministic",
    messages=[{"role": "user", "content": "hello"}],
):
    print(chunk)
```
