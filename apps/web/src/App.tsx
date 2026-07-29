import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  eventWebSocketProtocols,
  eventWebSocketUrl,
  streamChat,
} from "./api";
import { displayOs, formatBytes, timeAgo } from "./format";
import { OperationsPanel } from "./OperationsPanel";
import { signInWithPasskey } from "./passkeys";
import type {
  ClusterEvent,
  ExecutionPlan,
  ModelManifest,
  NetworkPolicy,
  NetworkPolicyResponse,
  NodeRecord,
  NodeResourcePolicy,
} from "./types";

type Mode = "simple" | "engineering";

export function App() {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<Mode>("simple");
  const [liveEvents, setLiveEvents] = useState<ClusterEvent[]>([]);
  const [connection, setConnection] = useState<"connected" | "reconnecting">(
    "reconnecting",
  );
  const [authGeneration, setAuthGeneration] = useState(0);

  const cluster = useQuery({ queryKey: ["cluster"], queryFn: api.cluster });
  const nodes = useQuery({ queryKey: ["nodes"], queryFn: api.nodes });
  const benchmarks = useQuery({
    queryKey: ["benchmarks"],
    queryFn: api.benchmarks,
  });
  const history = useQuery({ queryKey: ["events"], queryFn: api.events });
  const network = useQuery({
    queryKey: ["network-policy"],
    queryFn: api.networkPolicy,
  });
  const models = useQuery({ queryKey: ["models"], queryFn: api.models });
  const runnableModels = useQuery({
    queryKey: ["runnable-models"],
    queryFn: api.runnableModels,
  });

  useEffect(() => {
    let socket: WebSocket | undefined;
    let retry: number | undefined;
    let closed = false;
    const connect = () => {
      if (closed) return;
      try {
        socket = new WebSocket(eventWebSocketUrl(), eventWebSocketProtocols());
      } catch {
        setConnection("reconnecting");
        retry = window.setTimeout(connect, 1_500);
        return;
      }
      socket.addEventListener("open", () => setConnection("connected"));
      socket.addEventListener("message", (message) => {
        try {
          const event = JSON.parse(String(message.data)) as ClusterEvent;
          setLiveEvents((current) =>
            [
              event,
              ...current.filter((item) => item.sequence !== event.sequence),
            ].slice(0, 50),
          );
          void queryClient.invalidateQueries({ queryKey: ["cluster"] });
          void queryClient.invalidateQueries({ queryKey: ["nodes"] });
          void queryClient.invalidateQueries({ queryKey: ["benchmarks"] });
          if (event.event_type.startsWith("model.")) {
            void queryClient.invalidateQueries({ queryKey: ["models"] });
            void queryClient.invalidateQueries({
              queryKey: ["runnable-models"],
            });
          }
          if (event.event_type.startsWith("network.")) {
            void queryClient.invalidateQueries({
              queryKey: ["network-policy"],
            });
          }
        } catch {
          // Invalid event frames are ignored and remain visible in daemon logs.
        }
      });
      socket.addEventListener("close", () => {
        setConnection("reconnecting");
        retry = window.setTimeout(connect, 1_500);
      });
    };
    connect();
    return () => {
      closed = true;
      if (retry) window.clearTimeout(retry);
      socket?.close();
    };
  }, [authGeneration, queryClient]);

  const events = useMemo(() => {
    const combined = [...liveEvents, ...(history.data ?? [])];
    return combined
      .filter(
        (event, index) =>
          combined.findIndex(
            (candidate) => candidate.sequence === event.sequence,
          ) === index,
      )
      .sort((a, b) => b.sequence - a.sequence)
      .slice(0, 20);
  }, [history.data, liveEvents]);

  const error =
    cluster.error ??
    nodes.error ??
    benchmarks.error ??
    history.error ??
    models.error ??
    runnableModels.error ??
    network.error;
  const networkMode = network.data?.policy.remote_enabled
    ? network.data.policy.managed_relay_enabled
      ? "Remote + relay"
      : "Remote direct"
    : "Local only";
  const runnableModelIds = runnableModels.data?.data.map(
    (model) => model.id,
  ) ?? ["constellation/mock"];

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#main" aria-label="Constellation home">
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span>Constellation</span>
        </a>
        <div
          className="mode-switch"
          role="group"
          aria-label="Interface detail level"
        >
          <button
            className={mode === "simple" ? "active" : ""}
            onClick={() => setMode("simple")}
            aria-pressed={mode === "simple"}
          >
            Simple
          </button>
          <button
            className={mode === "engineering" ? "active" : ""}
            onClick={() => setMode("engineering")}
            aria-pressed={mode === "engineering"}
          >
            Engineering
          </button>
        </div>
        <div className={`connection ${connection}`} role="status">
          <span aria-hidden="true" />{" "}
          {connection === "connected" ? "Live" : "Reconnecting"}
        </div>
        <AuthControl
          onChange={() => {
            setAuthGeneration((current) => current + 1);
            void queryClient.invalidateQueries();
          }}
        />
      </header>

      <main id="main" tabIndex={-1}>
        {error ? (
          <ErrorBanner
            error={error}
            onRetry={() => void queryClient.invalidateQueries()}
          />
        ) : null}
        <section className="hero" aria-labelledby="cluster-heading">
          <div>
            <p className="eyebrow">PRIVATE AI COMPUTE</p>
            <h1 id="cluster-heading">Your computers, working as one.</h1>
            <p className="hero-copy">
              {cluster.data?.message ?? "Checking your private compute pool…"}
            </p>
          </div>
          <div className="privacy-badge">
            <span aria-hidden="true">⌁</span>
            <div>
              <strong>{networkMode}</strong>
              <small>
                {network.data?.policy.remote_enabled
                  ? "Explicit byte quota · Content logs off"
                  : "No relay · No cloud · Content logs off"}
              </small>
            </div>
          </div>
        </section>

        <section className="stat-grid" aria-label="Cluster summary">
          <Stat
            label="Ready computers"
            value={String(cluster.data?.ready_nodes ?? "—")}
            detail={`${cluster.data?.total_nodes ?? 0} registered`}
          />
          <Stat
            label="Usable AI memory"
            value={
              cluster.data ? formatBytes(cluster.data.usable_memory_bytes) : "—"
            }
            detail="After safety reserves"
          />
          <Stat
            label="Active runtime"
            value={cluster.data?.active_runtime ?? "—"}
            detail="Capability checked"
          />
          <Stat
            label="Network policy"
            value={networkMode}
            detail={
              network.data?.remote_kill_switch_engaged
                ? "Emergency stop engaged"
                : network.data?.policy.remote_enabled
                  ? `${formatBytes(network.data.remote_bytes_used_this_month)} used this month`
                  : "Remote compute disabled"
            }
          />
        </section>

        {mode === "engineering" && network.data ? (
          <NetworkControls value={network.data} />
        ) : null}

        <div className="primary-grid">
          <section
            className="panel nodes-panel"
            aria-labelledby="computers-heading"
          >
            <div className="panel-heading">
              <div>
                <p className="eyebrow">COMPUTE POOL</p>
                <h2 id="computers-heading">Computers</h2>
              </div>
              <button
                className="secondary-button"
                onClick={() => void queryClient.invalidateQueries()}
                disabled={nodes.isFetching}
              >
                Refresh
              </button>
            </div>
            {nodes.isLoading ? <LoadingRows /> : null}
            {nodes.data?.length === 0 ? (
              <EmptyState
                title="This computer is starting"
                body="The daemon will add its verified local hardware automatically."
              />
            ) : null}
            <div className="node-list">
              {nodes.data?.map((node) => (
                <NodeRow
                  key={node.id}
                  node={node}
                  benchmark={benchmarks.data?.find(
                    (item) => item.node_id === node.id,
                  )}
                  engineering={mode === "engineering"}
                />
              ))}
            </div>
          </section>

          <PlannerPanel
            models={runnableModelIds}
            onPlan={(plan) =>
              setLiveEvents((current) => [
                {
                  sequence: Date.now(),
                  event_type: "plan.simulated",
                  payload: { plan_id: plan.id },
                  created_at: new Date().toISOString(),
                },
                ...current,
              ])
            }
          />
        </div>

        <ModelLibraryPanel
          models={models.data ?? []}
          loading={models.isLoading}
        />

        {mode === "engineering" ? <OperationsPanel /> : null}

        <div className="secondary-grid">
          <ChatPanel models={runnableModelIds} />
          <section className="panel" aria-labelledby="activity-heading">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">AUDITABLE STATE</p>
                <h2 id="activity-heading">Activity</h2>
              </div>
            </div>
            {events.length === 0 ? (
              <EmptyState
                title="No activity yet"
                body="Node changes, benchmarks, plans, and workloads will appear here without prompt content."
              />
            ) : null}
            <ol className="activity-list">
              {events.map((event) => (
                <li key={event.sequence}>
                  <span className="activity-dot" aria-hidden="true" />
                  <div>
                    <strong>{event.event_type.replaceAll(".", " ")}</strong>
                    <small>
                      {timeAgo(event.created_at)} · event {event.sequence}
                    </small>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        </div>
      </main>
    </div>
  );
}

function NetworkControls({ value }: { value: NetworkPolicyResponse }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<NetworkPolicy>(value.policy);
  useEffect(() => setDraft(value.policy), [value.policy]);
  const update = useMutation({
    mutationFn: api.updateNetworkPolicy,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["network-policy"] });
    },
  });
  const disable = useMutation({
    mutationFn: api.disableRemoteNetworking,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["network-policy"] });
    },
  });
  const error = update.error ?? disable.error;
  return (
    <section className="panel network-panel" aria-labelledby="network-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">PRIVACY BOUNDARY</p>
          <h2 id="network-heading">Remote networking</h2>
        </div>
        <button
          className="danger-button"
          onClick={() => disable.mutate()}
          disabled={disable.isPending || value.remote_kill_switch_engaged}
        >
          {value.remote_kill_switch_engaged
            ? "Emergency stop engaged"
            : "Stop remote traffic"}
        </button>
      </div>
      <p className="muted">
        Remote paths stay disabled until you set a monthly byte budget. A
        managed relay has a separate opt-in and sees encrypted traffic metadata,
        never plaintext content.
      </p>
      <div className="network-controls">
        <label>
          <input
            type="checkbox"
            checked={draft.remote_enabled}
            disabled={value.remote_kill_switch_engaged}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                remote_enabled: event.target.checked,
              }))
            }
          />
          Allow remote trusted nodes
        </label>
        <label>
          Monthly quota (GiB)
          <input
            type="number"
            min="0"
            max="100000"
            value={draft.monthly_remote_byte_quota / 1024 ** 3}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                monthly_remote_byte_quota: Math.round(
                  Number(event.target.value) * 1024 ** 3,
                ),
              }))
            }
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={draft.managed_relay_enabled}
            disabled={!draft.remote_enabled || value.remote_kill_switch_engaged}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                managed_relay_enabled: event.target.checked,
              }))
            }
          />
          Allow managed relay
        </label>
        <button
          className="primary-button"
          disabled={update.isPending || value.remote_kill_switch_engaged}
          onClick={() => update.mutate(draft)}
        >
          Save network policy
        </button>
      </div>
      {error ? (
        <p className="inline-error" role="alert">
          {error.message}
        </p>
      ) : null}
    </section>
  );
}

function Stat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <article className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function NodeRow({
  node,
  benchmark,
  engineering,
}: {
  node: NodeRecord;
  benchmark?: {
    tokens_per_second: number;
    time_to_first_token_ms: number;
    network_latency_ms: number;
  };
  engineering: boolean;
}) {
  const accelerator = node.capabilities.accelerator;
  return (
    <article className={`node-row status-${node.status}`}>
      <div className="node-icon" aria-hidden="true">
        {displayOs(node.os).slice(0, 1)}
      </div>
      <div className="node-main">
        <div className="node-title">
          <h3>{node.name}</h3>
          <span className="status-pill">{node.status}</span>
        </div>
        <p>
          {displayOs(node.os)} · {node.architecture} ·{" "}
          {node.capabilities.cpu_model}
        </p>
        <div className="node-metrics">
          <span>{formatBytes(node.capabilities.memory_total_bytes)} RAM</span>
          <span>
            {accelerator
              ? `${accelerator.model} · ${formatBytes(accelerator.memory_bytes)}`
              : "CPU inference"}
          </span>
          <span>{node.capabilities.user_active ? "User active" : "Idle"}</span>
        </div>
        {engineering ? (
          <div className="engineering-details">
            <code>{node.id}</code>
            <span>Runtimes: {node.capabilities.runtimes.join(", ")}</span>
            <span>
              {benchmark
                ? `${benchmark.tokens_per_second.toFixed(1)} tok/s · ${benchmark.time_to_first_token_ms.toFixed(0)} ms TTFT · ${benchmark.network_latency_ms.toFixed(1)} ms link`
                : "Awaiting benchmark"}
            </span>
            <PolicyControls nodeId={node.id} />
          </div>
        ) : null}
      </div>
    </article>
  );
}

function PolicyControls({ nodeId }: { nodeId: string }) {
  const queryClient = useQueryClient();
  const policy = useQuery({
    queryKey: ["node-policy", nodeId],
    queryFn: () => api.nodePolicy(nodeId),
  });
  const update = useMutation({
    mutationFn: (value: NodeResourcePolicy) =>
      api.updateNodePolicy(nodeId, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["node-policy", nodeId],
      });
      await queryClient.invalidateQueries({ queryKey: ["cluster"] });
    },
  });
  if (!policy.data) return <span>Loading owner policy…</span>;
  const set = (changes: Partial<NodeResourcePolicy>) =>
    update.mutate({ ...policy.data, ...changes });
  return (
    <details className="policy-controls">
      <summary>Owner resource limits</summary>
      <label>
        System RAM reserve
        <input
          type="number"
          min={15}
          max={100}
          value={policy.data.system_memory_reserve_percent}
          onChange={(event) =>
            set({ system_memory_reserve_percent: Number(event.target.value) })
          }
        />
        <span>% (minimum 15%)</span>
      </label>
      <label>
        <input
          type="checkbox"
          checked={policy.data.allow_on_battery}
          onChange={(event) => set({ allow_on_battery: event.target.checked })}
        />
        Allow work on battery
      </label>
      <label>
        <input
          type="checkbox"
          checked={policy.data.allow_when_user_active}
          onChange={(event) =>
            set({ allow_when_user_active: event.target.checked })
          }
        />
        Allow work while this computer is in use
      </label>
      {update.error ? (
        <span className="inline-error">{update.error.message}</span>
      ) : null}
    </details>
  );
}

function PlannerPanel({
  models,
  onPlan,
}: {
  models: string[];
  onPlan: (plan: ExecutionPlan) => void;
}) {
  const [policy, setPolicy] = useState("balanced");
  const [workloadClass, setWorkloadClass] = useState("interactive");
  const [model, setModel] = useState("constellation/mock");
  const mutation = useMutation({
    mutationFn: () => api.plan(policy, workloadClass, model),
    onSuccess: onPlan,
  });
  return (
    <section className="panel planner-panel" aria-labelledby="planner-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">AUTOPILOT</p>
          <h2 id="planner-heading">Plan a workload</h2>
        </div>
      </div>
      <p className="muted">
        Simulate placement before content is sent. Privacy and owner limits are
        checked first.
      </p>
      <label>
        Model
        <select
          value={model}
          onChange={(event) => setModel(event.target.value)}
        >
          {models.map((candidate) => (
            <option key={candidate} value={candidate}>
              {candidate}
            </option>
          ))}
        </select>
      </label>
      <label>
        Policy
        <select
          value={policy}
          onChange={(event) => setPolicy(event.target.value)}
        >
          <option value="balanced">Balanced</option>
          <option value="fastest">Fastest</option>
          <option value="most_private">Most Private</option>
          <option value="lowest_power">Lowest Power</option>
          <option value="keep_this_computer_responsive">
            Keep This Computer Responsive
          </option>
        </select>
      </label>
      <label>
        Workload
        <select
          value={workloadClass}
          onChange={(event) => setWorkloadClass(event.target.value)}
        >
          <option value="interactive">Interactive chat</option>
          <option value="batch">Batch requests</option>
          <option value="background">Background work</option>
        </select>
      </label>
      <button
        className="primary-button"
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending}
      >
        {mutation.isPending ? "Evaluating…" : "Simulate plan"}
      </button>
      {mutation.error ? (
        <p className="inline-error" role="alert">
          {mutation.error.message}
        </p>
      ) : null}
      {mutation.data ? (
        <PlanResult plan={mutation.data} />
      ) : (
        <div className="plan-placeholder">
          <span aria-hidden="true">⌁</span>
          <p>No execution decision has been made.</p>
        </div>
      )}
    </section>
  );
}

function PlanResult({ plan }: { plan: ExecutionPlan }) {
  return (
    <div className="plan-result" aria-live="polite">
      <div className="plan-score">
        <strong>{plan.strategy.replaceAll("_", " ")}</strong>
        <span>{Math.round(plan.confidence * 100)}% confidence</span>
      </div>
      <p>{plan.reasons[0]}</p>
      <dl>
        <div>
          <dt>Estimated speed</dt>
          <dd>{plan.estimated_tokens_per_second.toFixed(1)} tok/s</dd>
        </div>
        <div>
          <dt>First response</dt>
          <dd>~{Math.round(plan.estimated_ttft_ms)} ms</dd>
        </div>
        <div>
          <dt>Data path</dt>
          <dd>
            {plan.privacy.leaves_local_network ? "Leaves LAN" : "Local only"}
          </dd>
        </div>
        <div>
          <dt>Content logs</dt>
          <dd>{plan.privacy.content_logged ? "On" : "Off"}</dd>
        </div>
      </dl>
      {plan.alternatives.length ? (
        <details>
          <summary>
            {plan.alternatives.length} alternative
            {plan.alternatives.length === 1 ? "" : "s"} considered
          </summary>
          <ul>
            {plan.alternatives.slice(0, 4).map((item) => (
              <li key={`${item.node_id}-${item.code}`}>{item.reason}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function ModelLibraryPanel({
  models,
  loading,
}: {
  models: ModelManifest[];
  loading: boolean;
}) {
  const queryClient = useQueryClient();
  const verify = useMutation({
    mutationFn: api.verifyModel,
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ["models"] }),
  });
  const pin = useMutation({
    mutationFn: ({ alias, pinned }: { alias: string; pinned: boolean }) =>
      api.pinModel(alias, pinned),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ["models"] }),
  });
  return (
    <section className="panel model-panel" aria-labelledby="models-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">VERIFIED WEIGHTS</p>
          <h2 id="models-heading">Model library</h2>
        </div>
        <span className="model-count">{models.length} imported</span>
      </div>
      {loading ? <LoadingRows /> : null}
      {!loading && models.length === 0 ? (
        <EmptyState
          title="No local models yet"
          body="Import a licensed GGUF with the Constellation CLI. Every file is verified before a runtime can load it."
        />
      ) : null}
      <div className="model-list">
        {models.map((model) => (
          <article className="model-row" key={model.alias}>
            <div className="model-main">
              <div className="node-title">
                <h3>{model.alias}</h3>
                {model.pinned ? (
                  <span className="status-pill">Pinned</span>
                ) : null}
              </div>
              <p>
                {model.format.toUpperCase()}
                {model.quantization ? ` · ${model.quantization}` : ""} ·{" "}
                {formatBytes(model.size_bytes)}
              </p>
              <code title={model.sha256}>{model.sha256.slice(0, 16)}…</code>
              <small>
                {model.chunks.length} verified chunk
                {model.chunks.length === 1 ? "" : "s"} ·{" "}
                {model.license.license_id}
              </small>
            </div>
            <div className="model-actions">
              <button
                className="secondary-button"
                disabled={verify.isPending}
                onClick={() => verify.mutate(model.alias)}
              >
                Verify
              </button>
              <button
                className="secondary-button"
                disabled={pin.isPending}
                onClick={() =>
                  pin.mutate({ alias: model.alias, pinned: !model.pinned })
                }
              >
                {model.pinned ? "Unpin" : "Pin"}
              </button>
            </div>
          </article>
        ))}
      </div>
      {verify.error || pin.error ? (
        <p className="inline-error" role="alert">
          {(verify.error ?? pin.error)?.message}
        </p>
      ) : null}
    </section>
  );
}

function ChatPanel({ models }: { models: string[] }) {
  const queryClient = useQueryClient();
  const [prompt, setPrompt] = useState("");
  const [model, setModel] = useState("constellation/mock");
  const [output, setOutput] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();
  const [saveHistory, setSaveHistory] = useState(false);
  const [conversationId, setConversationId] = useState<string>();
  const conversations = useQuery({
    queryKey: ["conversations"],
    queryFn: api.conversations,
  });
  const savedMessages = useQuery({
    queryKey: ["conversation-messages", conversationId],
    queryFn: () => api.conversationMessages(conversationId ?? ""),
    enabled: Boolean(conversationId),
  });
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!prompt.trim() || working) return;
    setOutput("");
    setError(undefined);
    setWorking(true);
    let completedOutput = "";
    try {
      let activeConversation = conversationId;
      if (saveHistory) {
        if (!activeConversation) {
          const created = await api.createConversation(prompt.slice(0, 80));
          activeConversation = created.id;
          setConversationId(created.id);
        }
        await api.appendConversationMessage(activeConversation, "user", prompt);
      }
      await streamChat(model, prompt, (delta) => {
        completedOutput += delta;
        setOutput((current) => current + delta);
      });
      if (saveHistory && activeConversation && completedOutput) {
        await api.appendConversationMessage(
          activeConversation,
          "assistant",
          completedOutput,
        );
        await queryClient.invalidateQueries({ queryKey: ["conversations"] });
        await queryClient.invalidateQueries({
          queryKey: ["conversation-messages", activeConversation],
        });
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Chat failed");
    } finally {
      setWorking(false);
    }
  };
  return (
    <section className="panel chat-panel" aria-labelledby="chat-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">PRIVATE CHAT</p>
          <h2 id="chat-heading">Test the cluster</h2>
        </div>
        <span className="model-pill">{model}</span>
      </div>
      <div
        className={`chat-output ${output ? "has-output" : ""}`}
        aria-live="polite"
      >
        {output || (
          <span>
            Deterministic output will stream here. Prompts are not written to
            operational logs.
          </span>
        )}
      </div>
      {saveHistory ? (
        <div className="conversation-history">
          <label htmlFor="conversation">Encrypted history</label>
          <select
            id="conversation"
            value={conversationId ?? ""}
            onChange={(event) => {
              const selected = event.target.value || undefined;
              setConversationId(selected);
              setOutput("");
            }}
          >
            <option value="">Start a new conversation</option>
            {conversations.data?.map((conversation) => (
              <option key={conversation.id} value={conversation.id}>
                {new Date(conversation.updated_at).toLocaleString()}
              </option>
            ))}
          </select>
          {savedMessages.data?.length ? (
            <ol>
              {savedMessages.data.map((message) => (
                <li key={message.id}>
                  <strong>{message.role}</strong>
                  <span>{message.content}</span>
                </li>
              ))}
            </ol>
          ) : null}
          {conversationId ? (
            <button
              className="secondary-button"
              type="button"
              onClick={() => {
                void api.deleteConversation(conversationId).then(async () => {
                  setConversationId(undefined);
                  setOutput("");
                  await queryClient.invalidateQueries({
                    queryKey: ["conversations"],
                  });
                });
              }}
            >
              Delete conversation
            </button>
          ) : null}
        </div>
      ) : null}
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="chat-model">Model</label>
        <select
          id="chat-model"
          value={model}
          onChange={(event) => setModel(event.target.value)}
        >
          {models.map((candidate) => (
            <option key={candidate} value={candidate}>
              {candidate}
            </option>
          ))}
        </select>
        <label htmlFor="prompt">Message</label>
        <textarea
          id="prompt"
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          rows={3}
          maxLength={8_000}
          placeholder="Ask the private cluster…"
        />
        <div className="form-footer">
          <label className="history-toggle">
            <input
              type="checkbox"
              checked={saveHistory}
              onChange={(event) => {
                setSaveHistory(event.target.checked);
                if (!event.target.checked) setConversationId(undefined);
              }}
            />
            Save encrypted history
          </label>
          <button
            className="primary-button"
            disabled={!prompt.trim() || working}
          >
            {working ? "Generating…" : "Send"}
          </button>
        </div>
        {error ? (
          <p className="inline-error" role="alert">
            {error}
          </p>
        ) : null}
      </form>
    </section>
  );
}

function AuthControl({ onChange }: { onChange: () => void }) {
  const [principalName, setPrincipalName] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();
  const [signedIn, setSignedIn] = useState(() =>
    Boolean(sessionStorage.getItem("constellation_api_key")),
  );
  const oidcProviders = useQuery({
    queryKey: ["oidc-login-providers"],
    queryFn: api.oidcProviders,
  });

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const code = query.get("code");
    const state = query.get("state");
    const providerId = sessionStorage.getItem("constellation_oidc_provider");
    if (!code || !state || !providerId || signedIn) return;
    query.delete("code");
    query.delete("state");
    query.delete("session_state");
    const remaining = query.toString();
    window.history.replaceState(
      {},
      "",
      `${window.location.pathname}${remaining ? `?${remaining}` : ""}${window.location.hash}`,
    );
    setWorking(true);
    setError(undefined);
    void api
      .finishOidcLogin(providerId, state, code)
      .then((session) => {
        sessionStorage.setItem("constellation_api_key", session.access_token);
        sessionStorage.removeItem("constellation_oidc_provider");
        setSignedIn(true);
        onChange();
      })
      .catch((caught: unknown) => {
        sessionStorage.removeItem("constellation_oidc_provider");
        setError(
          caught instanceof Error
            ? caught.message
            : "Organization sign-in failed",
        );
      })
      .finally(() => setWorking(false));
  }, [onChange, signedIn]);

  if (signedIn) {
    return (
      <button
        className="auth-button"
        type="button"
        onClick={() => {
          sessionStorage.removeItem("constellation_api_key");
          setSignedIn(false);
          onChange();
        }}
      >
        Sign out
      </button>
    );
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setWorking(true);
    setError(undefined);
    try {
      await signInWithPasskey(principalName.trim());
      setSignedIn(true);
      onChange();
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Passkey sign-in failed",
      );
    } finally {
      setWorking(false);
    }
  };

  const beginOidc = async (providerId: string) => {
    setWorking(true);
    setError(undefined);
    try {
      const start = await api.beginOidcLogin(providerId);
      sessionStorage.setItem("constellation_oidc_provider", providerId);
      window.location.assign(start.authorization_url);
    } catch (caught) {
      setWorking(false);
      setError(
        caught instanceof Error
          ? caught.message
          : "Organization sign-in failed",
      );
    }
  };

  return (
    <details className="auth-control">
      <summary>Sign in</summary>
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="passkey-principal">Account name</label>
        <input
          id="passkey-principal"
          value={principalName}
          onChange={(event) => setPrincipalName(event.target.value)}
          autoComplete="username webauthn"
          maxLength={128}
          required
        />
        <button className="primary-button" disabled={working}>
          {working ? "Waiting for passkey…" : "Continue with passkey"}
        </button>
        {oidcProviders.data?.map((provider) => (
          <button
            className="secondary-button"
            type="button"
            disabled={working}
            key={provider.id}
            onClick={() => void beginOidc(provider.id)}
          >
            Continue with {new URL(provider.issuer).hostname}
          </button>
        ))}
        {error ? <p role="alert">{error}</p> : null}
      </form>
    </details>
  );
}

function ErrorBanner({
  error,
  onRetry,
}: {
  error: Error;
  onRetry: () => void;
}) {
  return (
    <div className="error-banner" role="alert">
      <div>
        <strong>Constellation is not reachable</strong>
        <p>{error.message}</p>
      </div>
      <button onClick={onRetry}>Retry</button>
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}

function LoadingRows() {
  return (
    <div className="loading-rows" aria-label="Loading computers">
      <i />
      <i />
      <i />
    </div>
  );
}
