//! Explicitly enabled, quota-bounded OpenAI-compatible cloud execution.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use constellation_core::{ClusterEvent, WorkloadId};
use constellation_runtime::RuntimeEvent;
use constellation_secrets::OsKeyring;
use constellation_teams::CloudAdapterPolicy;
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};
use url::Url;
use uuid::Uuid;

use crate::repository::Repository;

/// Built-in provider adapter identifier.
pub const OPENAI_COMPATIBLE_PROVIDER: &str = "com.constellation.cloud.openai-compatible";

/// Hard reservation calculated before an external request is sent.
#[derive(Clone, Copy)]
pub struct CloudReservation {
    /// Worst-case monthly spend charged to this request.
    pub cost_micros: u64,
    /// Maximum request-plus-response bytes admitted for this request.
    pub network_bytes: u64,
}

/// Parses a public model alias into policy identity and exact provider model.
#[must_use]
pub fn parse_model_alias(alias: &str) -> Option<(Uuid, &str)> {
    let remainder = alias.strip_prefix("cloud/")?;
    let (policy_id, model) = remainder.split_once('/')?;
    if model.is_empty() || model.len() > 256 {
        return None;
    }
    Some((Uuid::parse_str(policy_id).ok()?, model))
}

/// Returns a stable public alias that cannot collide with local runtime models.
#[must_use]
pub fn model_alias(policy_id: Uuid, model: &str) -> String {
    format!("cloud/{policy_id}/{model}")
}

/// Validates that a requested model is explicitly enabled by one executable policy.
pub fn validate_execution_policy(policy: &CloudAdapterPolicy, model: &str) -> Result<()> {
    if !policy.enabled
        || policy.provider_plugin != OPENAI_COMPATIBLE_PROVIDER
        || !policy.models.iter().any(|allowed| allowed == model)
        || policy.endpoint.is_none()
    {
        bail!("cloud model is not enabled by an executable policy");
    }
    Ok(())
}

/// Calculates conservative cost and network reservations using byte-count input tokens.
#[must_use]
pub fn reservation(
    policy: &CloudAdapterPolicy,
    input: &str,
    max_output_tokens: u32,
) -> CloudReservation {
    let input_token_upper_bound = u64::try_from(input.len()).unwrap_or(u64::MAX);
    let output_tokens = u64::from(max_output_tokens);
    let input_cost = prorated_cost(
        input_token_upper_bound,
        policy.input_cost_per_million_tokens_micros,
    );
    let output_cost = prorated_cost(output_tokens, policy.output_cost_per_million_tokens_micros);
    let network_bytes = input_token_upper_bound
        .saturating_add(output_tokens.saturating_mul(32))
        .saturating_add(128 * 1024);
    CloudReservation {
        cost_micros: input_cost.saturating_add(output_cost),
        network_bytes,
    }
}

/// Starts one bounded provider stream. Neither request nor response content is logged or stored.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Security bounds and streaming parser stay visible together.
pub fn execute_stream(
    policy: &CloudAdapterPolicy,
    model: String,
    input: String,
    max_output_tokens: u32,
    workload_id: WorkloadId,
    reservation: CloudReservation,
    repository: Repository,
    events: broadcast::Sender<ClusterEvent>,
) -> Result<mpsc::Receiver<RuntimeEvent>> {
    validate_execution_policy(policy, &model)?;
    let endpoint = chat_endpoint(
        policy
            .endpoint
            .as_ref()
            .context("cloud endpoint is absent")?,
    )?;
    let secret = OsKeyring::new("com.constellation.provider", &policy.credential_reference)
        .load_secret_string()
        .context("cloud credential reference is unavailable")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_mins(15))
        .user_agent("Constellation/0.1 cloud-adapter")
        .build()
        .context("build cloud HTTPS client")?;
    let input_rate = policy.input_cost_per_million_tokens_micros;
    let output_rate = policy.output_cost_per_million_tokens_micros;
    let (sender, receiver) = mpsc::channel(256);
    tokio::spawn(async move {
        let _ignored = sender.send(RuntimeEvent::Loading { progress: 1.0 }).await;
        let request_bytes = u64::try_from(input.len()).unwrap_or(u64::MAX);
        let response = client
            .post(endpoint)
            .bearer_auth(secret.as_str())
            .json(&json!({
                "model": model,
                "messages": [{"role": "user", "content": input}],
                "stream": true,
                "stream_options": {"include_usage": true},
                "max_tokens": max_output_tokens,
            }))
            .send()
            .await;
        let Ok(response) = response else {
            send_failure(&sender, false, "cloud provider connection failed").await;
            return;
        };
        if !response.status().is_success() {
            send_failure(&sender, false, "cloud provider rejected the request").await;
            return;
        }
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        let mut response_bytes = 0_u64;
        let mut output_started = false;
        let mut finished = false;
        let mut input_tokens = u32::try_from(input.split_whitespace().count()).unwrap_or(u32::MAX);
        let mut output_tokens = 0_u32;
        let mut finish_reason = "stop".to_owned();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                send_failure(
                    &sender,
                    output_started,
                    "cloud provider stream was interrupted",
                )
                .await;
                return;
            };
            response_bytes =
                response_bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if request_bytes.saturating_add(response_bytes) > reservation.network_bytes {
                send_failure(
                    &sender,
                    output_started,
                    "cloud provider exceeded the reserved network budget",
                )
                .await;
                return;
            }
            buffer.extend_from_slice(&chunk);
            normalize_crlf(&mut buffer);
            while let Some(boundary) = find_frame_boundary(&buffer) {
                let frame = buffer.drain(..boundary).collect::<Vec<_>>();
                buffer.drain(..2);
                for line in frame.split(|byte| *byte == b'\n') {
                    let Some(payload) = line.strip_prefix(b"data: ") else {
                        continue;
                    };
                    if payload == b"[DONE]" {
                        finished = true;
                        continue;
                    }
                    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
                        send_failure(
                            &sender,
                            output_started,
                            "cloud provider returned an invalid stream frame",
                        )
                        .await;
                        return;
                    };
                    if let Some(delta) = value
                        .pointer("/choices/0/delta/content")
                        .and_then(Value::as_str)
                    {
                        output_started = true;
                        output_tokens = output_tokens.saturating_add(
                            u32::try_from(delta.split_whitespace().count()).unwrap_or(u32::MAX),
                        );
                        if sender
                            .send(RuntimeEvent::TextDelta(delta.to_owned()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some(reason) = value
                        .pointer("/choices/0/finish_reason")
                        .and_then(Value::as_str)
                    {
                        finish_reason = reason.to_owned();
                    }
                    if let Some(usage) = value.get("usage") {
                        input_tokens = usage
                            .get("prompt_tokens")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(input_tokens);
                        output_tokens = usage
                            .get("completion_tokens")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(output_tokens);
                    }
                }
            }
        }
        if !finished {
            send_failure(
                &sender,
                output_started,
                "cloud provider ended without a completion marker",
            )
            .await;
            return;
        }
        let actual_cost = prorated_cost(u64::from(input_tokens), input_rate)
            .saturating_add(prorated_cost(u64::from(output_tokens), output_rate));
        let actual_network = request_bytes.saturating_add(response_bytes);
        if actual_cost > reservation.cost_micros || actual_network > reservation.network_bytes {
            send_failure(
                &sender,
                output_started,
                "cloud provider exceeded its usage reservation",
            )
            .await;
            return;
        }
        if let Ok(Some(event)) = repository
            .complete_cloud_usage(workload_id, actual_cost, actual_network)
            .await
        {
            let _ignored = events.send(event);
        } else {
            send_failure(&sender, output_started, "cloud usage reconciliation failed").await;
            return;
        }
        let _ignored = sender
            .send(RuntimeEvent::Finished {
                input_tokens,
                output_tokens,
                finish_reason,
            })
            .await;
    });
    Ok(receiver)
}

fn prorated_cost(tokens: u64, rate_per_million: u64) -> u64 {
    tokens
        .saturating_mul(rate_per_million)
        .saturating_add(999_999)
        / 1_000_000
}

fn chat_endpoint(base: &Url) -> Result<Url> {
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        bail!("cloud endpoint must be an exact credential-free HTTPS URL");
    }
    let mut normalized = base.clone();
    if !normalized.path().ends_with('/') {
        normalized.set_path(&format!("{}/", normalized.path()));
    }
    normalized
        .join("chat/completions")
        .context("construct cloud chat endpoint")
}

fn normalize_crlf(buffer: &mut Vec<u8>) {
    let mut index = 0;
    while index + 1 < buffer.len() {
        if buffer[index] == b'\r' && buffer[index + 1] == b'\n' {
            buffer.remove(index);
        } else {
            index += 1;
        }
    }
}

fn find_frame_boundary(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\n\n")
}

async fn send_failure(
    sender: &mpsc::Sender<RuntimeEvent>,
    output_started: bool,
    message: &'static str,
) {
    let _ignored = sender
        .send(RuntimeEvent::Failure {
            code: "cloud_execution_failed".to_owned(),
            message: message.to_owned(),
            retryable: !output_started,
            output_started,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::{model_alias, parse_model_alias, reservation};
    use constellation_teams::CloudAdapterPolicy;
    use uuid::Uuid;

    #[test]
    fn aliases_preserve_provider_model_names() {
        let id = Uuid::now_v7();
        let alias = model_alias(id, "vendor/model-v1");
        assert_eq!(parse_model_alias(&alias), Some((id, "vendor/model-v1")));
    }

    #[test]
    fn reservation_uses_byte_upper_bound_and_output_budget() {
        let policy = CloudAdapterPolicy {
            input_cost_per_million_tokens_micros: 1_000_000,
            output_cost_per_million_tokens_micros: 2_000_000,
            ..CloudAdapterPolicy::default()
        };
        let reserved = reservation(&policy, "abcd", 10);
        assert_eq!(reserved.cost_micros, 24);
        assert!(reserved.network_bytes > 320);
    }
}
