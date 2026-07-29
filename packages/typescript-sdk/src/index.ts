export interface ConstellationClientOptions {
  baseUrl?: string;
  apiKey?: string;
  fetch?: typeof globalThis.fetch;
}

export interface Model {
  id: string;
  object: "model";
  owned_by: string;
  created: number;
}

export interface ModelList {
  object: "list";
  data: Model[];
}

export interface ChatMessage {
  role: "system" | "developer" | "user" | "assistant" | "tool";
  content: unknown;
}

export interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  stream?: boolean;
  max_tokens?: number;
  max_completion_tokens?: number;
  tools?: unknown[];
  response_format?: unknown;
}

export interface ChatCompletion {
  id: string;
  object: "chat.completion";
  model: string;
  choices: Array<{
    index: number;
    message: ChatMessage;
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface ChatCompletionChunk {
  id: string;
  object: "chat.completion.chunk";
  model: string;
  choices: Array<{
    index: number;
    delta: Partial<ChatMessage>;
    finish_reason: string | null;
  }>;
  error?: { message: string; type: string; code: string };
}

export interface ClusterSummary {
  ready_nodes: number;
  total_nodes: number;
  usable_memory_bytes: number;
  active_runtime: string;
  local_only: boolean;
  message: string;
}

export interface ClusterEvent {
  sequence: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export class ConstellationError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly traceId?: string,
  ) {
    super(message);
    this.name = "ConstellationError";
  }
}

export class ConstellationClient {
  readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: ConstellationClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "http://127.0.0.1:4317").replace(
      /\/$/,
      "",
    );
    this.apiKey = options.apiKey;
    this.fetcher = options.fetch ?? globalThis.fetch;
    if (!this.fetcher)
      throw new Error("A Fetch API implementation is required");
  }

  models(): Promise<ModelList> {
    return this.request("/v1/models");
  }

  chatCompletions(request: ChatCompletionRequest): Promise<ChatCompletion> {
    return this.request("/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ ...request, stream: false }),
    });
  }

  responses(
    request: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request("/v1/responses", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  embeddings(
    request: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request("/v1/embeddings", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  cluster(): Promise<ClusterSummary> {
    return this.request("/constellation/v1/cluster");
  }

  devices(): Promise<Array<Record<string, unknown>>> {
    return this.request("/constellation/v1/devices");
  }

  events(after = 0, limit = 100): Promise<ClusterEvent[]> {
    const query = new URLSearchParams({
      after: String(after),
      limit: String(limit),
    });
    return this.request(`/constellation/v1/events?${query}`);
  }

  async *streamChat(
    request: ChatCompletionRequest,
    signal?: AbortSignal,
  ): AsyncGenerator<ChatCompletionChunk> {
    const response = await this.fetcher(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ ...request, stream: true }),
      signal,
    });
    if (!response.ok || !response.body) await this.throwResponse(response);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder
          .decode(value, { stream: true })
          .replace(/\r\n/g, "\n");
        let boundary = buffer.indexOf("\n\n");
        while (boundary >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const data = frame
            .split("\n")
            .find((line) => line.startsWith("data: "))
            ?.slice(6);
          if (data && data !== "[DONE]")
            yield JSON.parse(data) as ChatCompletionChunk;
          boundary = buffer.indexOf("\n\n");
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      ...init,
      headers: { ...this.headers(), ...init.headers },
    });
    if (!response.ok) return this.throwResponse(response);
    return (await response.json()) as T;
  }

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      ...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
    };
  }

  private async throwResponse(response: Response): Promise<never> {
    let message = `Constellation request failed (${response.status})`;
    let code: string | undefined;
    let traceId: string | undefined;
    try {
      const value = (await response.json()) as {
        error?: { message?: string; code?: string; trace_id?: string };
      };
      message = value.error?.message ?? message;
      code = value.error?.code;
      traceId = value.error?.trace_id;
    } catch {
      // The status remains the normalized fallback.
    }
    throw new ConstellationError(message, response.status, code, traceId);
  }
}
