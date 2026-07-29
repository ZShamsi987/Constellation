import assert from "node:assert/strict";
import test from "node:test";

import OpenAI from "openai";

const baseURL = process.env.CONSTELLATION_COMPAT_URL;

test("official OpenAI TypeScript client", { skip: !baseURL }, async () => {
  const client = new OpenAI({
    apiKey: process.env.CONSTELLATION_COMPAT_KEY ?? "local-test-key",
    baseURL: `${baseURL}/v1`,
    maxRetries: 0,
  });
  const models = await client.models.list();
  assert.ok(models.data.some((model) => model.id === "constellation/mock"));

  const completion = await client.chat.completions.create({
    model: "constellation/mock",
    messages: [{ role: "user", content: "official TypeScript client" }],
  });
  assert.match(
    completion.choices[0].message.content,
    /official TypeScript client/,
  );

  const stream = await client.chat.completions.create({
    model: "constellation/mock",
    messages: [{ role: "user", content: "stream contract" }],
    stream: true,
  });
  let text = "";
  for await (const chunk of stream)
    text += chunk.choices[0]?.delta?.content ?? "";
  assert.match(text, /stream contract/);

  const response = await client.responses.create({
    model: "constellation/mock",
    input: "responses contract",
  });
  assert.equal(response.object, "response");
});
