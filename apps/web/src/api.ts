import type {
  BenchmarkReport,
  ClusterEvent,
  ClusterSummary,
  ConversationMessage,
  ConversationRecord,
  ExecutionPlan,
  ModelManifest,
  NetworkPolicy,
  NetworkPolicyResponse,
  NodeRecord,
  NodeResourcePolicy,
  RunnableModel,
  PluginRecord,
  PrincipalRecord,
  TeamRecord,
  WorkflowRunResponse,
  WorkflowSummary,
} from "./types";

const apiBase =
  (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/$/, "") ??
  "";

function headers(): HeadersInit {
  const key = sessionStorage.getItem("constellation_api_key");
  return {
    "Content-Type": "application/json",
    ...(key ? { Authorization: `Bearer ${key}` } : {}),
  };
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    headers: { ...headers(), ...init?.headers },
  });
  const body = await response.text();
  if (!response.ok) {
    let message = body || `Request failed (${response.status})`;
    try {
      const parsed = JSON.parse(body) as { error?: { message?: string } };
      message = parsed.error?.message ?? message;
    } catch {
      // The HTTP status and plain body are already actionable.
    }
    throw new Error(message);
  }
  return JSON.parse(body) as T;
}

export const api = {
  cluster: () => json<ClusterSummary>("/constellation/v1/cluster"),
  nodes: () => json<NodeRecord[]>("/constellation/v1/devices"),
  nodePolicy: (nodeId: string) =>
    json<NodeResourcePolicy>(`/constellation/v1/devices/${nodeId}/policy`),
  updateNodePolicy: (nodeId: string, policy: NodeResourcePolicy) =>
    json<NodeResourcePolicy>(`/constellation/v1/devices/${nodeId}/policy`, {
      method: "PATCH",
      body: JSON.stringify(policy),
    }),
  benchmarks: () => json<BenchmarkReport[]>("/constellation/v1/benchmarks"),
  networkPolicy: () =>
    json<NetworkPolicyResponse>("/constellation/v1/network/policy"),
  updateNetworkPolicy: (policy: NetworkPolicy) =>
    json<NetworkPolicyResponse>("/constellation/v1/network/policy", {
      method: "PATCH",
      body: JSON.stringify(policy),
    }),
  disableRemoteNetworking: () =>
    json<NetworkPolicyResponse>("/constellation/v1/emergency/remote-disable", {
      method: "POST",
    }),
  events: () => json<ClusterEvent[]>("/constellation/v1/events?limit=50"),
  models: () => json<ModelManifest[]>("/constellation/v1/models"),
  runnableModels: () =>
    json<{ object: "list"; data: RunnableModel[] }>("/v1/models"),
  verifyModel: (alias: string) =>
    json<ModelManifest>("/constellation/v1/models/verify", {
      method: "POST",
      body: JSON.stringify({ alias }),
    }),
  pinModel: (alias: string, pinned: boolean) =>
    json<ModelManifest>("/constellation/v1/models/pin", {
      method: "PATCH",
      body: JSON.stringify({ alias, pinned }),
    }),
  conversations: () =>
    json<ConversationRecord[]>("/constellation/v1/chat/conversations"),
  createConversation: (title?: string) =>
    json<ConversationRecord>("/constellation/v1/chat/conversations", {
      method: "POST",
      body: JSON.stringify({ title, temporary: false }),
    }),
  conversationMessages: (conversationId: string) =>
    json<ConversationMessage[]>(
      `/constellation/v1/chat/conversations/${conversationId}/messages`,
    ),
  appendConversationMessage: (
    conversationId: string,
    role: "user" | "assistant",
    content: string,
  ) =>
    json<ConversationMessage>(
      `/constellation/v1/chat/conversations/${conversationId}/messages`,
      {
        method: "POST",
        body: JSON.stringify({ role, content }),
      },
    ),
  deleteConversation: async (conversationId: string) => {
    const response = await fetch(
      `${apiBase}/constellation/v1/chat/conversations/${conversationId}`,
      { method: "DELETE", headers: headers() },
    );
    if (!response.ok) throw new Error(`Delete failed (${response.status})`);
  },
  plan: (policy: string, workloadClass: string, model = "constellation/mock") =>
    json<ExecutionPlan>("/constellation/v1/plans/simulate", {
      method: "POST",
      body: JSON.stringify({
        model,
        required_runtime: model === "constellation/mock" ? "mock" : "llama.cpp",
        estimated_memory_bytes: 1024 * 1024 * 1024,
        class: workloadClass,
        policy,
      }),
    }),
  workflows: () =>
    json<{ data: WorkflowSummary[] }>("/constellation/v1/workflows"),
  createWorkflow: (definition: unknown) =>
    json<{ id: string }>("/constellation/v1/workflows", {
      method: "POST",
      body: JSON.stringify({ definition }),
    }),
  startWorkflow: (workflowId: string) =>
    json<WorkflowRunResponse>(
      `/constellation/v1/workflows/${workflowId}/runs`,
      { method: "POST", body: JSON.stringify({ inputs: {} }) },
    ),
  workflowRun: (runId: string) =>
    json<WorkflowRunResponse>(`/constellation/v1/workflow-runs/${runId}`),
  plugins: () => json<{ data: PluginRecord[] }>("/constellation/v1/plugins"),
  principals: () =>
    json<{ data: PrincipalRecord[] }>("/constellation/v1/principals"),
  createServicePrincipal: (name: string, scopes: string[]) =>
    json<{ principal: PrincipalRecord; api_key: string }>(
      "/constellation/v1/principals",
      {
        method: "POST",
        body: JSON.stringify({ name, role: "service", scopes }),
      },
    ),
  createHumanPrincipal: (name: string, role: "admin" | "operator" | "viewer") =>
    json<{ principal: PrincipalRecord; api_key: null }>(
      "/constellation/v1/principals",
      {
        method: "POST",
        body: JSON.stringify({ name, role, scopes: [] }),
      },
    ),
  beginPasskeyRegistration: (principalId: string, name: string) =>
    json<PasskeyCeremony>(
      "/constellation/v1/auth/passkeys/registration/begin",
      {
        method: "POST",
        body: JSON.stringify({ principal_id: principalId, name }),
      },
    ),
  finishPasskeyRegistration: (ceremonyId: string, credential: unknown) =>
    json<{ principal_id: string; name: string }>(
      "/constellation/v1/auth/passkeys/registration/finish",
      {
        method: "POST",
        body: JSON.stringify({ ceremony_id: ceremonyId, credential }),
      },
    ),
  beginPasskeyLogin: (principalName: string) =>
    json<PasskeyCeremony>("/constellation/v1/auth/passkeys/login/begin", {
      method: "POST",
      body: JSON.stringify({ principal_name: principalName }),
    }),
  finishPasskeyLogin: (ceremonyId: string, credential: unknown) =>
    json<{
      access_token: string;
      expires_at: string;
      principal: PrincipalRecord;
    }>("/constellation/v1/auth/passkeys/login/finish", {
      method: "POST",
      body: JSON.stringify({ ceremony_id: ceremonyId, credential }),
    }),
  oidcProviders: () =>
    json<Array<{ id: string; issuer: string }>>(
      "/constellation/v1/auth/oidc/providers",
    ),
  beginOidcLogin: (providerId: string) =>
    json<{ authorization_url: string; expires_in_seconds: number }>(
      "/constellation/v1/auth/oidc/login/begin",
      {
        method: "POST",
        body: JSON.stringify({ provider_id: providerId }),
      },
    ),
  finishOidcLogin: (providerId: string, state: string, code: string) =>
    json<{
      access_token: string;
      expires_at: string;
      principal: PrincipalRecord;
    }>("/constellation/v1/auth/oidc/login/finish", {
      method: "POST",
      body: JSON.stringify({ provider_id: providerId, state, code }),
    }),
  teams: () => json<{ data: TeamRecord[] }>("/constellation/v1/teams"),
  createTeam: (name: string) =>
    json<TeamRecord>("/constellation/v1/teams", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  authProviders: () =>
    json<
      Array<{
        id: string;
        kind: "oidc" | "saml";
        issuer: string;
        client_id: string;
        credential_reference: string;
        redirect_uri: string;
        allowed_groups: string[];
        enabled: boolean;
      }>
    >("/constellation/v1/auth-providers"),
  putAuthProvider: (provider: {
    id: string;
    kind: "oidc";
    issuer: string;
    client_id: string;
    credential_reference: string;
    redirect_uri: string;
    allowed_groups: string[];
    enabled: boolean;
  }) =>
    json("/constellation/v1/auth-providers", {
      method: "POST",
      body: JSON.stringify(provider),
    }),
  linkExternalIdentity: (
    providerId: string,
    principalId: string,
    subject: string,
  ) =>
    json(`/constellation/v1/auth-providers/${providerId}/links`, {
      method: "POST",
      body: JSON.stringify({ principal_id: principalId, subject }),
    }),
  cloudPolicies: () =>
    json<
      Array<{
        id: string;
        provider_plugin: string;
        enabled: boolean;
        regions: string[];
        models: string[];
        monthly_cost_limit_micros: number;
        monthly_network_limit_bytes: number;
        credential_reference: string;
        endpoint?: string;
        input_cost_per_million_tokens_micros: number;
        output_cost_per_million_tokens_micros: number;
      }>
    >("/constellation/v1/cloud-adapters"),
  putCloudPolicy: (policy: {
    id: string;
    provider_plugin: string;
    enabled: boolean;
    regions: string[];
    models: string[];
    monthly_cost_limit_micros: number;
    monthly_network_limit_bytes: number;
    credential_reference: string;
    endpoint: string;
    input_cost_per_million_tokens_micros: number;
    output_cost_per_million_tokens_micros: number;
  }) =>
    json("/constellation/v1/cloud-adapters", {
      method: "POST",
      body: JSON.stringify(policy),
    }),
};

export interface PasskeyCeremony {
  ceremony_id: string;
  public_key: {
    publicKey: Record<string, unknown>;
  };
  expires_in_seconds: number;
}

export async function streamChat(
  model: string,
  prompt: string,
  onDelta: (delta: string) => void,
): Promise<void> {
  const response = await fetch(`${apiBase}/v1/chat/completions`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      stream: true,
    }),
  });
  if (!response.ok || !response.body) {
    const body = await response.text();
    throw new Error(body || `Chat failed (${response.status})`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      const data = frame
        .split("\n")
        .find((line) => line.startsWith("data: "))
        ?.slice(6);
      if (!data || data === "[DONE]") continue;
      const chunk = JSON.parse(data) as {
        choices?: Array<{ delta?: { content?: string } }>;
        error?: { message?: string };
      };
      if (chunk.error?.message) throw new Error(chunk.error.message);
      const delta = chunk.choices?.[0]?.delta?.content;
      if (delta) onDelta(delta);
    }
  }
}

export function eventWebSocketUrl(): string {
  const base = apiBase || window.location.origin;
  const url = new URL("/constellation/v1/events/live", base);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export function eventWebSocketProtocols(): string[] {
  const key = sessionStorage.getItem("constellation_api_key");
  return key
    ? ["constellation.events.v1", `constellation.bearer.${key}`]
    : ["constellation.events.v1"];
}
