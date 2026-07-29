export type OperatingSystem = "windows" | "mac_os" | "linux" | "unknown";
export type NodeStatus =
  "joining" | "ready" | "suspect" | "offline" | "revoked" | "draining";

export interface Accelerator {
  vendor: string;
  model: string;
  memory_bytes: number;
  backends: string[];
}

export interface NodeCapabilities {
  cpu_model: string;
  logical_cores: number;
  memory_total_bytes: number;
  memory_available_bytes: number;
  accelerator?: Accelerator;
  runtimes: string[];
  on_battery: boolean;
  user_active: boolean;
  temperature_celsius?: number;
  thermal_throttling?: boolean;
}

export interface NodeRecord {
  id: string;
  name: string;
  os: OperatingSystem;
  architecture: string;
  status: NodeStatus;
  capabilities: NodeCapabilities;
  last_seen_at: string;
}

export interface NodeResourcePolicy {
  system_memory_reserve_percent: number;
  system_memory_reserve_bytes: number;
  accelerator_memory_reserve_percent: number;
  accelerator_memory_reserve_bytes: number;
  allow_on_battery: boolean;
  allow_when_user_active: boolean;
  max_temperature_celsius?: number;
}

export interface BenchmarkReport {
  node_id: string;
  runtime: string;
  model: string;
  tokens_per_second: number;
  time_to_first_token_ms: number;
  network_latency_ms: number;
  network_bandwidth_mbps: number;
  jitter_ms: number;
  packet_loss: number;
  sample_count: number;
  kind: "measured" | "estimated" | "unavailable";
  measured_at: string;
}

export interface ClusterSummary {
  ready_nodes: number;
  total_nodes: number;
  usable_memory_bytes: number;
  active_runtime: string;
  local_only: boolean;
  message: string;
}

export interface NetworkPolicy {
  remote_enabled: boolean;
  managed_relay_enabled: boolean;
  self_hosted_relay?: string;
  monthly_remote_byte_quota: number;
}

export interface NetworkPolicyResponse {
  policy: NetworkPolicy;
  remote_kill_switch_engaged: boolean;
  remote_bytes_used_this_month: number;
}

export interface RejectedCandidate {
  node_id: string;
  code: string;
  reason: string;
}

export interface ExecutionPlan {
  id: string;
  workload_id: string;
  strategy: "single_node" | "independent_routing" | "replicated";
  selected_nodes: string[];
  estimated_ttft_ms: number;
  estimated_tokens_per_second: number;
  estimated_memory_bytes: Record<string, number>;
  estimated_network_bytes: number;
  confidence: number;
  reasons: string[];
  alternatives: RejectedCandidate[];
  privacy: {
    prompt_nodes: string[];
    model_weight_nodes: string[];
    uses_relay: boolean;
    leaves_local_network: boolean;
    uses_cloud: boolean;
    content_logged: boolean;
  };
  replan_triggers: string[];
  created_at: string;
}

export interface ClusterEvent {
  sequence: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ModelManifest {
  schema_version: number;
  alias: string;
  sha256: string;
  size_bytes: number;
  chunk_size_bytes: number;
  chunks: Array<{ index: number; sha256: string; size_bytes: number }>;
  format: string;
  quantization?: string;
  source: string;
  license: { license_id: string; accepted_at: string; source: string };
  pinned: boolean;
  created_at: string;
  verified_at: string;
}

export interface RunnableModel {
  id: string;
  object: "model";
  owned_by: string;
  created: number;
}

export interface ConversationRecord {
  id: string;
  temporary: false;
  created_at: string;
  updated_at: string;
}

export interface ConversationMessage {
  id: string;
  conversation_id: string;
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  created_at: string;
}

export interface WorkflowSummary {
  id: string;
  name: string;
  revision: number;
  sha256: string;
  updated_at: string;
}

export interface WorkflowRunResponse {
  run: {
    id: string;
    workflow_id: string;
    status:
      | "pending"
      | "running"
      | "waiting_approval"
      | "completed"
      | "failed"
      | "cancelled";
    steps: Record<string, { status: string; attempt: number }>;
    created_at: string;
    updated_at: string;
  };
  ready_steps: string[];
}

export interface DeclarativeUiPanel {
  title: string;
  icon: string;
  data_sources: string[];
  layout: unknown;
}

export interface PluginRecord {
  manifest: {
    id: string;
    version: string;
    kind: "tool" | "runtime" | "provider" | "ui";
    permissions: Array<Record<string, unknown> | string>;
    metadata: {
      name: string;
      description: string;
      license: string;
      publisher: string;
      ui?: DeclarativeUiPanel;
    };
  };
  enabled: boolean;
}

export interface PrincipalRecord {
  id: string;
  name: string;
  role: "owner" | "admin" | "operator" | "viewer" | "node" | "service";
  scopes: string[];
  active: boolean;
  created_at: string;
}

export interface TeamRecord {
  id: string;
  name: string;
  created_at?: string;
}
