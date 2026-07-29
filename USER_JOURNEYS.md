# User Journeys

## First local request

1. Install the signed desktop package; the local daemon starts on login.
2. Create a cluster and store its authority in native credential storage.
3. Review detected hardware and runtime guidance.
4. Import a local GGUF model or select the deterministic mock model.
5. Send a chat request and see streaming output, placement, privacy path, and metrics.

Success: no external account, Docker, public listener, or configuration-file edit.

## Add a nearby computer

1. Select Add Computer and create an eight-character, ten-minute invitation.
2. Install the node on the second computer and enter the code or scan the QR.
3. Confirm both device fingerprints and approve on the controller.
4. Run the fast compute/network benchmark.
5. Review the new capacity and recommended workload use.

Failure states include expired/used codes, attempt exhaustion, clock skew, incompatible protocol, unreachable controller, and denied local resource policy; each provides a recovery action.

## Run and inspect a workload

1. Submit through chat, CLI, or the OpenAI-compatible endpoint.
2. Autopilot filters unsafe candidates, estimates feasible plans, and selects one.
3. The user sees the selected node, expected performance, reason, alternatives, confidence, and data path.
4. Actual performance is recorded without logging content and compared with the estimate.

## Handle a node loss

1. Heartbeats become suspect after 15 seconds and offline after 30.
2. New requests avoid the node immediately after the offline transition.
3. A request with no emitted output may retry once; a streamed request ends with preserved partial output and `generation_interrupted`.
4. The activity view explains the failure and whether a subsequent attempt restarted.

## Revoke a device

1. An Owner or Admin confirms revocation.
2. The controller blocks certificate renewal and invalidates active sessions and peer tickets.
3. Workloads replan; locally cached models remain unless the node owner separately deletes them.
4. The audit log records actor, target, time, and outcome without sensitive content.
