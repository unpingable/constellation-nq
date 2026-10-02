# PagerDuty route runbook

This is the operator procedure for NQ's PagerDuty Events API v2 route. The
contract is in [`NOTIFICATIONS.md`](NOTIFICATIONS.md#pagerduty-events-api-v2).
No component emits PagerDuty conditions yet
([`PAGERDUTY_ALERT_MAP.md`](PAGERDUTY_ALERT_MAP.md)); every event below is one
an operator or site script writes and submits.

## 1. Create the integration

In PagerDuty, add an **Events API v2** integration to the service that should
receive Constellation alerts and copy its integration key (32 hexadecimal
characters). That integration is all NQ uses. NQ needs no REST API token, user
account or acknowledgment permission. Event Orchestration routing keys that are
not 32 hexadecimal characters are refused (`routing_key_malformed`).

Treat the key as a secret: anyone holding it can open and resolve alerts on
that service. Keep it out of repositories, manifests, reports, shell history
and ticket text.

## 2. Configure the route

```toml
[[notification_routes]]
reference = "pagerduty-ops"
transport = "pagerduty"
routing_key_env = "NQ_PAGERDUTY_OPS_ROUTING_KEY"
timeout_ms = 10000
max_response_bytes = 4096
```

```sh
nq --config /etc/nq/nq.toml config check
```

The configuration holds only the variable name. The endpoint is fixed in NQ and
cannot be configured.

## 3. Supply the key

Provide the variable to the process that runs `nq notification submit` or
`resubmit`, and to nothing else.

For a systemd unit or timer that submits intents, prefer an environment file
readable only by root:

```sh
install -m 0600 -o root -g root /dev/null /etc/nq/pagerduty-ops.env
# Write NQ_PAGERDUTY_OPS_ROUTING_KEY=<key> into it with an editor; do not echo it.
```

```ini
[Service]
EnvironmentFile=/etc/nq/pagerduty-ops.env
```

Avoid `Environment=NQ_PAGERDUTY_OPS_ROUTING_KEY=...` in a unit file or drop-in.
That value appears in `systemctl show` output, which unprivileged users can
read. `LoadCredential=` is not consumed: NQ reads only the named environment
variable.

For an interactive shell, read the key from an operator-owned file in the same
command that uses it, so it never enters history or the terminal:

```sh
NQ_PAGERDUTY_OPS_ROUTING_KEY="$(cat ~/pagerduty-routing-key)" \
  nq --config /etc/nq/nq.toml notification submit \
  --intent ./trigger.json --route pagerduty-ops --enable-network
```

## 4. Trigger and resolve a test condition

Write a canonical v2 intent: compact JSON with sorted keys and no trailing
newline. For example, with `jq -cjS . source.json > trigger.json`:

```json
{"action":"trigger","attention_kind":"operator_assertion","attention_policy_digest":"sha256:<64 hex of your operator policy>","attention_policy_id":"operator-test","condition":{"component":"nq","rule":"nq-no-fresh-acquisition","site":"crow-lab","target_class":"demo"},"destination_identity":"pagerduty:pagerduty-ops","inspection_reference":"nq notification inspect","route_reference":"pagerduty-ops","schema":"nq.notification_delivery_intent.v2","severity":"critical","stable_event_id":"test-trigger-1","summary":"TEST: NQ route qualification","transition_id":"test-1"}
```

Submit it with the key supplied as in step 3 and `--enable-network`. The
result shows `delivery_state` and `dedup_key`
(`constellation:crow-lab:nq:nq-no-fresh-acquisition:demo`). Check it:

```sh
nq --config /etc/nq/nq.toml notification inspect --notification-id ID
```

`accepted` means PagerDuty answered 202 with `status: success`: the event was
enqueued. It does not mean an incident exists. A well-formed but wrong or
revoked routing key also gets 202 `success`, and PagerDuty then drops the event
without any error. **The only confirmation is the alert appearing in
PagerDuty.** Confirm that one alert is open with that dedup key.

To resolve it, submit the same intent with `"action":"resolve"` and a new
`stable_event_id` (for example `test-resolve-1`). Keep the condition exactly
the same, including `target_class`: a resolve for a different dedup key is
also `accepted` and resolves nothing. Confirm the alert is resolved.
A repeated trigger for the same condition with a new `stable_event_id` updates
the same alert and does not open another.

## 5. When a delivery fails

`nq status export` shows `notification`/`outbox` as
`delivery_failure_unresolved` when, on some route, the newest terminal outcome
for a condition is a failure. Refusals count, so a missing or malformed key
shows here, except the deliberate `network_dispatch_not_explicitly_enabled`.
The detail lists those failures per route with `reason`, `http_status` and
`retry_class`. `notification inspect --notification-id ID` adds PagerDuty's
message under `pagerduty.last_event.detail`.

A healthy status does not prove that anyone was paged. `accepted` is what
NQ can see, and a wrong but well-formed key is `accepted` too; check
PagerDuty itself.

| `reason` | Next step |
|---|---|
| `routing_key_unavailable` | The variable is not set for that process; fix step 3, then resubmit. |
| `routing_key_malformed` | The value is not 32 hex characters; recopy the integration key, then resubmit. |
| `network_dispatch_not_explicitly_enabled` | Resubmit with `--enable-network`. |
| `rate_limited`, `server_error`, `connect_failed` | Retryable; resubmit after a pause. |
| `rejected` | Permanent for that request: PagerDuty refused the event (for example an invalid payload or a key it reports as malformed). Read the PagerDuty message, fix the cause, then resubmit. A wrong but well-formed key does not appear here; it is `accepted`. |
| `timeout_after_dispatch`, `transport_error_or_response_loss`, `success_not_confirmed`, or a claim without outcome | PagerDuty may have the event. Resubmitting the newest record for the condition is safe, because it carries the same dedup key. |

```sh
NQ_PAGERDUTY_OPS_ROUTING_KEY="$(cat ~/pagerduty-routing-key)" \
  nq --config /etc/nq/nq.toml notification resubmit \
  --notification-id ID --stable-event-id test-trigger-1-r1 --enable-network
```

Resubmit only the newest record for a condition; NQ refuses older ones and
names the later record. Resending an older trigger after a resolve would reopen
a cleared alert, and resending an older resolve after a new trigger would close
the new alert. If a later record exists, decide from the condition's current
state and submit a fresh trigger or resolve instead.

NQ never resubmits on its own. The original record keeps its outcome. Rollover
keeps refusing while a `pending` or `unknown` record exists, so a single
timeout blocks rollover for the life of that store.

## 6. After a plan change or key rotation

After a PagerDuty plan downgrade (for example to Free), a service change or a
key rotation, repeat step 4 with new event ids. Confirm that:

- the service and its Events API v2 integration still exist, and the key is
  the one in the environment file;
- the trigger is `accepted` *and* an alert appears in PagerDuty, and the
  resolve closes it. `accepted` alone does not show that the key is right;
- someone is actually notified. A downgrade can remove escalation steps,
  schedules or notification channels. NQ cannot see that: `accepted` only
  means PagerDuty enqueued the event.

When rotating the key, replace the environment file and restart or re-run the
submitting unit. Old records do not hold the key, so nothing in the NQ store
needs to change.
