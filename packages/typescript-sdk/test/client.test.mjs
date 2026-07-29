import assert from "node:assert/strict";
import test from "node:test";
import { ConstellationClient, ConstellationError } from "../dist/index.js";

test("adds bearer authentication and normalizes errors", async () => {
  let authorization;
  const client = new ConstellationClient({
    apiKey: "test-key",
    fetch: async (_url, init) => {
      authorization = init?.headers.Authorization;
      return new Response(
        JSON.stringify({
          error: { message: "denied", code: "forbidden", trace_id: "trace" },
        }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    },
  });
  await assert.rejects(client.cluster(), (error) => {
    assert.ok(error instanceof ConstellationError);
    assert.equal(error.code, "forbidden");
    return true;
  });
  assert.equal(authorization, "Bearer test-key");
});
