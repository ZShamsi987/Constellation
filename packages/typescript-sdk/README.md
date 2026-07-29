# Constellation TypeScript SDK

```ts
import { ConstellationClient } from "@constellation/sdk";

const client = new ConstellationClient({ baseUrl: "http://127.0.0.1:4317" });
for await (const chunk of client.streamChat({
  model: "constellation/mock",
  messages: [{ role: "user", content: "hello" }],
})) {
  process.stdout.write(String(chunk.choices[0]?.delta.content ?? ""));
}
```

The client follows the implemented `openapi/constellation.openapi.yaml` contract and exposes
normalized trace-aware errors. Raw request content is never logged by the SDK.
