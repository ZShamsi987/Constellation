import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { registerPasskey } from "./passkeys";
import type { DeclarativeUiPanel, PluginRecord } from "./types";

const starterWorkflow = JSON.stringify(
  {
    version: 1,
    name: "Private artifact",
    description: "A durable local workflow starter",
    steps: [
      {
        id: "write",
        type: "artifact",
        name: "result.txt",
        media_type: "text/plain",
        value: "Created by Constellation",
        timeout_seconds: 30,
        retry_limit: 1,
      },
    ],
  },
  null,
  2,
);

type VisualStep = {
  id: string;
  type: "artifact" | "inference" | "approval" | "tool";
  depends_on?: string[];
  when?: { operator: "succeeded" | "failed"; step: string };
  timeout_seconds: number;
  retry_limit: number;
  name?: string;
  media_type?: string;
  value?: string;
  model?: string;
  input?: string;
  max_output_tokens?: number;
  prompt?: string;
  required_role?: string;
  tool?: string;
  arguments?: unknown;
  sandboxed?: boolean;
};

type VisualDefinition = {
  version: number;
  name: string;
  description: string;
  steps: VisualStep[];
};

export function OperationsPanel() {
  return (
    <section className="operations" aria-labelledby="operations-heading">
      <div className="section-heading">
        <div>
          <p className="eyebrow">DURABLE AUTOMATION</p>
          <h2 id="operations-heading">Workflows and administration</h2>
        </div>
        <p className="muted">
          Definitions, inputs, and artifacts are encrypted. Administrative
          records remain content-free.
        </p>
      </div>
      <div className="operations-grid">
        <WorkflowCard />
        <PluginCard />
        <IdentityCard />
        <ProviderCard />
      </div>
    </section>
  );
}

function WorkflowCard() {
  const queryClient = useQueryClient();
  const workflows = useQuery({
    queryKey: ["workflows"],
    queryFn: api.workflows,
  });
  const [definition, setDefinition] = useState(starterWorkflow);
  const [editor, setEditor] = useState<"visual" | "json">("visual");
  const [runId, setRunId] = useState<string>();
  const create = useMutation({
    mutationFn: () => api.createWorkflow(JSON.parse(definition) as unknown),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["workflows"] });
    },
  });
  const start = useMutation({
    mutationFn: api.startWorkflow,
    onSuccess: (response) => setRunId(response.run.id),
  });
  const run = useQuery({
    queryKey: ["workflow-run", runId],
    queryFn: () => api.workflowRun(runId ?? ""),
    enabled: Boolean(runId),
    refetchInterval: (query) => {
      const status = query.state.data?.run.status;
      return status === "running" || status === "pending" ? 1_000 : false;
    },
  });
  const error = create.error ?? start.error ?? run.error ?? workflows.error;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    try {
      JSON.parse(definition);
      create.mutate();
    } catch {
      // The inline error below provides the actionable result.
    }
  };
  const validJson = useMemo(() => {
    try {
      JSON.parse(definition);
      return true;
    } catch {
      return false;
    }
  }, [definition]);
  const visualDefinition = useMemo(() => {
    try {
      const parsed = JSON.parse(definition) as VisualDefinition;
      return Array.isArray(parsed.steps) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }, [definition]);
  return (
    <article className="panel operations-card">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">WORKFLOW ENGINE</p>
          <h3>Runs</h3>
        </div>
        <span className="model-count">
          {workflows.data?.data.length ?? 0} definitions
        </span>
      </div>
      <div className="editor-switch" role="group" aria-label="Workflow editor">
        <button
          type="button"
          className={editor === "visual" ? "active" : ""}
          onClick={() => setEditor("visual")}
        >
          Visual builder
        </button>
        <button
          type="button"
          className={editor === "json" ? "active" : ""}
          onClick={() => setEditor("json")}
        >
          JSON
        </button>
      </div>
      <form onSubmit={submit}>
        {editor === "visual" && visualDefinition ? (
          <VisualWorkflowBuilder
            definition={visualDefinition}
            onChange={(value) => setDefinition(JSON.stringify(value, null, 2))}
          />
        ) : (
          <label>
            Versioned JSON definition
            <textarea
              value={definition}
              onChange={(event) => setDefinition(event.target.value)}
              rows={8}
              spellCheck={false}
            />
          </label>
        )}
        <button
          className="primary-button"
          disabled={!validJson || create.isPending}
        >
          Validate and save
        </button>
      </form>
      {!validJson ? (
        <p className="inline-error" role="alert">
          Definition is not valid JSON.
        </p>
      ) : null}
      <ul className="compact-list">
        {workflows.data?.data.map((workflow) => (
          <li key={workflow.id}>
            <div>
              <strong>{workflow.name}</strong>
              <small>revision {workflow.revision}</small>
            </div>
            <button
              className="secondary-button"
              disabled={start.isPending}
              onClick={() => start.mutate(workflow.id)}
            >
              Run
            </button>
          </li>
        ))}
      </ul>
      {run.data ? (
        <div className="run-status" role="status">
          <strong>{run.data.run.status.replaceAll("_", " ")}</strong>
          <code>{run.data.run.id}</code>
          <small>
            {Object.entries(run.data.run.steps)
              .map(([id, step]) => `${id}: ${step.status}`)
              .join(" · ")}
          </small>
        </div>
      ) : null}
      {error ? <p className="inline-error">{error.message}</p> : null}
    </article>
  );
}

function newVisualStep(type: VisualStep["type"], index: number): VisualStep {
  const common = {
    id: `step_${index + 1}`,
    type,
    timeout_seconds: 300,
    retry_limit: type === "approval" ? 0 : 1,
  } as const;
  if (type === "inference") {
    return {
      ...common,
      model: "constellation/mock",
      input: "{{prompt}}",
      max_output_tokens: 256,
    };
  }
  if (type === "approval") {
    return {
      ...common,
      prompt: "Approve the next step",
      required_role: "operator",
    };
  }
  if (type === "tool") {
    return {
      ...common,
      tool: "com.constellation.example",
      arguments: {},
      sandboxed: true,
    };
  }
  return {
    ...common,
    name: "result.txt",
    media_type: "text/plain",
    value: "{{result}}",
  };
}

function VisualWorkflowBuilder({
  definition,
  onChange,
}: {
  definition: VisualDefinition;
  onChange: (definition: VisualDefinition) => void;
}) {
  const updateStep = (index: number, step: VisualStep) => {
    const previousId = definition.steps[index]?.id;
    const steps = definition.steps.map((current, position) => {
      if (position === index) return step;
      if (!previousId || previousId === step.id) return current;
      return {
        ...current,
        depends_on: current.depends_on?.map((dependency) =>
          dependency === previousId ? step.id : dependency,
        ),
        when:
          current.when?.step === previousId
            ? { ...current.when, step: step.id }
            : current.when,
      };
    });
    onChange({ ...definition, steps });
  };
  return (
    <div className="workflow-builder">
      <label>
        Workflow name
        <input
          value={definition.name}
          maxLength={128}
          onChange={(event) =>
            onChange({ ...definition, name: event.target.value })
          }
        />
      </label>
      <div className="workflow-canvas" aria-label="Workflow dependency graph">
        {definition.steps.map((step, index) => (
          <VisualStepCard
            key={`${index}-${step.id}`}
            step={step}
            index={index}
            steps={definition.steps}
            onChange={(value) => updateStep(index, value)}
            onRemove={() =>
              onChange({
                ...definition,
                steps: definition.steps
                  .filter((_current, position) => position !== index)
                  .map((current) => ({
                    ...current,
                    depends_on: current.depends_on?.filter(
                      (dependency) => dependency !== step.id,
                    ),
                    when:
                      current.when?.step === step.id ? undefined : current.when,
                  })),
              })
            }
          />
        ))}
      </div>
      <div className="builder-actions" aria-label="Add workflow step">
        {(["inference", "tool", "approval", "artifact"] as const).map(
          (type) => (
            <button
              key={type}
              type="button"
              className="secondary-button"
              onClick={() =>
                onChange({
                  ...definition,
                  steps: [
                    ...definition.steps,
                    newVisualStep(type, definition.steps.length),
                  ],
                })
              }
            >
              + {type}
            </button>
          ),
        )}
      </div>
    </div>
  );
}

function VisualStepCard({
  step,
  index,
  steps,
  onChange,
  onRemove,
}: {
  step: VisualStep;
  index: number;
  steps: VisualStep[];
  onChange: (step: VisualStep) => void;
  onRemove: () => void;
}) {
  const dependency = step.depends_on?.[0] ?? "";
  const changeType = (type: VisualStep["type"]) => {
    const replacement = newVisualStep(type, index);
    onChange({
      ...replacement,
      id: step.id,
      depends_on: step.depends_on,
      when: step.when,
    });
  };
  return (
    <article className="workflow-step-card">
      {dependency ? (
        <span className="workflow-connector" aria-hidden="true" />
      ) : null}
      <div className="step-card-heading">
        <strong>{index + 1}</strong>
        <select
          aria-label={`Step ${index + 1} type`}
          value={step.type}
          onChange={(event) =>
            changeType(event.target.value as VisualStep["type"])
          }
        >
          <option value="inference">Inference</option>
          <option value="tool">Sandboxed tool</option>
          <option value="approval">Human approval</option>
          <option value="artifact">Encrypted artifact</option>
        </select>
        <button
          type="button"
          className="icon-button"
          onClick={onRemove}
          aria-label={`Remove ${step.id}`}
        >
          ×
        </button>
      </div>
      <label>
        Step ID
        <input
          value={step.id}
          onChange={(event) => onChange({ ...step, id: event.target.value })}
        />
      </label>
      <label>
        Depends on
        <select
          value={dependency}
          onChange={(event) => {
            const value = event.target.value;
            onChange({
              ...step,
              depends_on: value ? [value] : [],
              when: value ? step.when : undefined,
            });
          }}
        >
          <option value="">No dependency (parallel)</option>
          {steps
            .filter((candidate, position) => position !== index && candidate.id)
            .map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.id}
              </option>
            ))}
        </select>
      </label>
      {dependency ? (
        <label>
          Condition
          <select
            value={step.when?.operator ?? "always"}
            onChange={(event) =>
              onChange({
                ...step,
                when:
                  event.target.value === "always"
                    ? undefined
                    : {
                        operator: event.target.value as "succeeded" | "failed",
                        step: dependency,
                      },
              })
            }
          >
            <option value="always">Always after dependency</option>
            <option value="succeeded">Only if succeeded</option>
            <option value="failed">Only if failed</option>
          </select>
        </label>
      ) : null}
      <VisualActionFields step={step} onChange={onChange} />
    </article>
  );
}

function VisualActionFields({
  step,
  onChange,
}: {
  step: VisualStep;
  onChange: (step: VisualStep) => void;
}) {
  if (step.type === "inference") {
    return (
      <>
        <label>
          Model
          <input
            value={step.model ?? ""}
            onChange={(event) =>
              onChange({ ...step, model: event.target.value })
            }
          />
        </label>
        <label>
          Input template
          <textarea
            rows={2}
            value={step.input ?? ""}
            onChange={(event) =>
              onChange({ ...step, input: event.target.value })
            }
          />
        </label>
      </>
    );
  }
  if (step.type === "tool") {
    return (
      <label>
        Tool ID
        <input
          value={step.tool ?? ""}
          onChange={(event) => onChange({ ...step, tool: event.target.value })}
        />
      </label>
    );
  }
  if (step.type === "approval") {
    return (
      <>
        <label>
          Approval prompt
          <input
            value={step.prompt ?? ""}
            onChange={(event) =>
              onChange({ ...step, prompt: event.target.value })
            }
          />
        </label>
        <label>
          Required role
          <select
            value={step.required_role ?? "operator"}
            onChange={(event) =>
              onChange({ ...step, required_role: event.target.value })
            }
          >
            <option value="owner">Owner</option>
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
          </select>
        </label>
      </>
    );
  }
  return (
    <>
      <label>
        Artifact name
        <input
          value={step.name ?? ""}
          onChange={(event) => onChange({ ...step, name: event.target.value })}
        />
      </label>
      <label>
        Value template
        <textarea
          rows={2}
          value={step.value ?? ""}
          onChange={(event) => onChange({ ...step, value: event.target.value })}
        />
      </label>
    </>
  );
}

function PluginCard() {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins });
  return (
    <article className="panel operations-card">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">WASI COMPONENTS</p>
          <h3>Plugins</h3>
        </div>
        <span className="model-count">Deny by default</span>
      </div>
      <p className="muted">
        Components remain disabled until an administrator grants an exact
        permission set for the installed digest.
      </p>
      {plugins.data?.data.length === 0 ? (
        <p className="empty-compact">No plugins installed.</p>
      ) : null}
      <ul className="compact-list plugin-list">
        {plugins.data?.data.map((plugin) => (
          <PluginRow key={plugin.manifest.id} plugin={plugin} />
        ))}
      </ul>
      {plugins.error ? (
        <p className="inline-error">{plugins.error.message}</p>
      ) : null}
    </article>
  );
}

function PluginRow({ plugin }: { plugin: PluginRecord }) {
  const panel = plugin.manifest.metadata.ui;
  return (
    <li className="plugin-entry">
      <div>
        <strong>{plugin.manifest.metadata.name}</strong>
        <small>
          {plugin.manifest.id} · {plugin.manifest.version} ·{" "}
          {plugin.manifest.kind}
        </small>
        <p>{plugin.manifest.metadata.description}</p>
        <span className={`status-pill ${plugin.enabled ? "" : "disabled"}`}>
          {plugin.enabled ? "granted" : "disabled"}
        </span>
      </div>
      {panel && plugin.enabled ? <DeclarativePanel panel={panel} /> : null}
    </li>
  );
}

function DeclarativePanel({ panel }: { panel: DeclarativeUiPanel }) {
  return (
    <aside className="declarative-panel" aria-label={panel.title}>
      <strong>{panel.title}</strong>
      <SafeLayout value={panel.layout} depth={0} />
    </aside>
  );
}

function SafeLayout({ value, depth }: { value: unknown; depth: number }) {
  if (depth > 8 || value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "number") {
    return <p>{String(value).slice(0, 2_048)}</p>;
  }
  if (Array.isArray(value)) {
    return (
      <div className="declarative-stack">
        {value.slice(0, 64).map((child, index) => (
          <SafeLayout key={index} value={child} depth={depth + 1} />
        ))}
      </div>
    );
  }
  if (typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  const type = typeof item.type === "string" ? item.type : "stack";
  if (type === "text" || type === "notice" || type === "metric") {
    const title = typeof item.title === "string" ? item.title : undefined;
    const text =
      typeof item.text === "string"
        ? item.text
        : typeof item.value === "string" || typeof item.value === "number"
          ? String(item.value)
          : undefined;
    return (
      <div className={`declarative-${type}`}>
        {title ? <strong>{title.slice(0, 256)}</strong> : null}
        {text ? <p>{text.slice(0, 2_048)}</p> : null}
      </div>
    );
  }
  return <SafeLayout value={item.children} depth={depth + 1} />;
}

function IdentityCard() {
  const queryClient = useQueryClient();
  const teams = useQuery({ queryKey: ["teams"], queryFn: api.teams });
  const principals = useQuery({
    queryKey: ["principals"],
    queryFn: api.principals,
  });
  const [teamName, setTeamName] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [humanName, setHumanName] = useState("");
  const [humanRole, setHumanRole] = useState<"admin" | "operator" | "viewer">(
    "operator",
  );
  const [issuedKey, setIssuedKey] = useState<string>();
  const [passkeyNotice, setPasskeyNotice] = useState<string>();
  const createTeam = useMutation({
    mutationFn: api.createTeam,
    onSuccess: async () => {
      setTeamName("");
      await queryClient.invalidateQueries({ queryKey: ["teams"] });
    },
  });
  const createService = useMutation({
    mutationFn: (name: string) =>
      api.createServicePrincipal(name, ["cluster_read", "workload_execute"]),
    onSuccess: async (result) => {
      setIssuedKey(result.api_key);
      setServiceName("");
      await queryClient.invalidateQueries({ queryKey: ["principals"] });
    },
  });
  const createHuman = useMutation({
    mutationFn: () => api.createHumanPrincipal(humanName.trim(), humanRole),
    onSuccess: async () => {
      setHumanName("");
      await queryClient.invalidateQueries({ queryKey: ["principals"] });
    },
  });
  const addPasskey = useMutation({
    mutationFn: (principal: { id: string; name: string }) =>
      registerPasskey(principal.id, `${principal.name} passkey`),
    onSuccess: (_result, principal) => {
      setPasskeyNotice(`Passkey registered for ${principal.name}.`);
    },
  });
  return (
    <article className="panel operations-card">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">TEAM ACCESS</p>
          <h3>Identities</h3>
        </div>
      </div>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (teamName.trim()) createTeam.mutate(teamName.trim());
        }}
      >
        <label>
          New team
          <input
            value={teamName}
            maxLength={128}
            onChange={(event) => setTeamName(event.target.value)}
          />
        </label>
        <button className="secondary-button" disabled={!teamName.trim()}>
          Create
        </button>
      </form>
      <div className="tag-row">
        {teams.data?.data.map((team) => (
          <span key={team.id}>{team.name}</span>
        ))}
      </div>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (humanName.trim()) createHuman.mutate();
        }}
      >
        <label>
          Human account
          <input
            value={humanName}
            maxLength={128}
            autoComplete="off"
            onChange={(event) => setHumanName(event.target.value)}
          />
        </label>
        <label>
          Role
          <select
            value={humanRole}
            onChange={(event) =>
              setHumanRole(event.target.value as typeof humanRole)
            }
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
        </label>
        <button className="secondary-button" disabled={!humanName.trim()}>
          Create account
        </button>
      </form>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (serviceName.trim()) createService.mutate(serviceName.trim());
        }}
      >
        <label>
          Scoped service identity
          <input
            value={serviceName}
            maxLength={128}
            onChange={(event) => setServiceName(event.target.value)}
          />
        </label>
        <button className="secondary-button" disabled={!serviceName.trim()}>
          Issue key
        </button>
      </form>
      {issuedKey ? (
        <div className="one-time-key" role="alert">
          <strong>Copy this key now. It is shown once.</strong>
          <code>{issuedKey}</code>
          <button
            className="secondary-button"
            onClick={() => setIssuedKey(undefined)}
          >
            I saved it
          </button>
        </div>
      ) : null}
      <ul className="compact-list">
        {principals.data?.data.map((principal) => (
          <li key={principal.id}>
            <div>
              <strong>{principal.name}</strong>
              <small>{principal.role}</small>
            </div>
            {principal.role !== "service" ? (
              <button
                className="secondary-button"
                disabled={addPasskey.isPending}
                onClick={() =>
                  addPasskey.mutate({ id: principal.id, name: principal.name })
                }
              >
                Add passkey
              </button>
            ) : null}
          </li>
        ))}
      </ul>
      {passkeyNotice ? <p className="success-note">{passkeyNotice}</p> : null}
      {(teams.error ??
      principals.error ??
      createTeam.error ??
      createService.error ??
      createHuman.error ??
      addPasskey.error) ? (
        <p className="inline-error">
          {
            (
              teams.error ??
              principals.error ??
              createTeam.error ??
              createService.error ??
              createHuman.error ??
              addPasskey.error
            )?.message
          }
        </p>
      ) : null}
    </article>
  );
}

function ProviderCard() {
  const queryClient = useQueryClient();
  const providers = useQuery({
    queryKey: ["auth-providers"],
    queryFn: api.authProviders,
  });
  const cloud = useQuery({
    queryKey: ["cloud-policies"],
    queryFn: api.cloudPolicies,
  });
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [redirectUri, setRedirectUri] = useState("");
  const [oidcCredential, setOidcCredential] = useState("");
  const [cloudEndpoint, setCloudEndpoint] = useState("");
  const [cloudModel, setCloudModel] = useState("");
  const [cloudRegion, setCloudRegion] = useState("");
  const [cloudCredential, setCloudCredential] = useState("");
  const saveOidc = useMutation({
    mutationFn: () =>
      api.putAuthProvider({
        id: crypto.randomUUID(),
        kind: "oidc",
        issuer: issuer.trim(),
        client_id: clientId.trim(),
        credential_reference: oidcCredential.trim(),
        redirect_uri: redirectUri.trim(),
        allowed_groups: [],
        enabled: true,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["auth-providers"] });
      await queryClient.invalidateQueries({
        queryKey: ["oidc-login-providers"],
      });
    },
  });
  const saveCloud = useMutation({
    mutationFn: () =>
      api.putCloudPolicy({
        id: crypto.randomUUID(),
        provider_plugin: "com.constellation.cloud.openai-compatible",
        enabled: true,
        regions: [cloudRegion.trim()],
        models: [cloudModel.trim()],
        monthly_cost_limit_micros: 10_000_000,
        monthly_network_limit_bytes: 10 * 1024 * 1024 * 1024,
        credential_reference: cloudCredential.trim(),
        endpoint: cloudEndpoint.trim(),
        input_cost_per_million_tokens_micros: 10_000_000,
        output_cost_per_million_tokens_micros: 30_000_000,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["cloud-policies"] });
      await queryClient.invalidateQueries({ queryKey: ["runnable-models"] });
    },
  });
  const providerReady =
    issuer.trim() &&
    clientId.trim() &&
    redirectUri.trim() &&
    oidcCredential.trim();
  const cloudReady =
    cloudEndpoint.trim() &&
    cloudModel.trim() &&
    cloudRegion.trim() &&
    cloudCredential.trim();
  const error =
    providers.error ?? cloud.error ?? saveOidc.error ?? saveCloud.error;
  return (
    <article className="panel operations-card provider-card">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">EXPLICIT EGRESS</p>
          <h3>Providers</h3>
        </div>
      </div>
      <p className="muted">
        Store provider secrets with the CLI first; this form accepts only their
        opaque vault reference.
      </p>
      <div className="provider-forms">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (providerReady) saveOidc.mutate();
          }}
        >
          <strong>OpenID Connect</strong>
          <label>
            Issuer
            <input
              type="url"
              placeholder="https://identity.example.com"
              value={issuer}
              onChange={(event) => setIssuer(event.target.value)}
            />
          </label>
          <label>
            Client ID
            <input
              value={clientId}
              onChange={(event) => setClientId(event.target.value)}
            />
          </label>
          <label>
            Exact redirect URL
            <input
              type="url"
              value={redirectUri}
              onChange={(event) => setRedirectUri(event.target.value)}
            />
          </label>
          <label>
            Credential reference
            <input
              value={oidcCredential}
              onChange={(event) => setOidcCredential(event.target.value)}
            />
          </label>
          <button
            className="secondary-button"
            disabled={!providerReady || saveOidc.isPending}
          >
            Discover and enable
          </button>
        </form>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (cloudReady) saveCloud.mutate();
          }}
        >
          <strong>OpenAI-compatible cloud</strong>
          <label>
            API base
            <input
              type="url"
              placeholder="https://provider.example/v1"
              value={cloudEndpoint}
              onChange={(event) => setCloudEndpoint(event.target.value)}
            />
          </label>
          <label>
            Exact model
            <input
              value={cloudModel}
              onChange={(event) => setCloudModel(event.target.value)}
            />
          </label>
          <label>
            Region
            <input
              value={cloudRegion}
              onChange={(event) => setCloudRegion(event.target.value)}
            />
          </label>
          <label>
            Credential reference
            <input
              value={cloudCredential}
              onChange={(event) => setCloudCredential(event.target.value)}
            />
          </label>
          <button
            className="secondary-button"
            disabled={!cloudReady || saveCloud.isPending}
          >
            Enable with hard limits
          </button>
        </form>
      </div>
      <div className="tag-row">
        {providers.data?.map((provider) => (
          <span key={provider.id}>
            {new URL(provider.issuer).hostname} · OIDC
          </span>
        ))}
        {cloud.data?.map((policy) => (
          <span key={policy.id}>{policy.models.join(", ")} · cloud</span>
        ))}
      </div>
      {error ? <p className="inline-error">{error.message}</p> : null}
    </article>
  );
}
