# Condition-bound pages through configured handlers

NQ's declared escalation policy governs rule, component, response class and route,
but only PagerDuty can consume its condition-bearing v2 intent. Local, Slack and
Discord receive v1 copies whose policy check has no condition. This leaves the
provider-independence requirement in NQ #30 and Cartography #95 incomplete.

Use the existing strict `nq.notification_delivery_intent.v2` fields for configured
Slack, Discord, local_file and PagerDuty routes. The operator-installed policy
remains the authority. Validate condition tokens and exact rule/component/class
and route membership before replay, credential resolution, custody effects or
I/O. Select the projection from the configured transport, rather than from the
presence of v2 fields. Condition-bearing pages remain explicitly page-class;
non-page/legacy v2 submissions retain their refusal. Missing policy never grants
Page authority. Preserve exact v1 behavior and history.

The v2 local artifact carries its condition, action and class explicitly in a
versioned local message, under the existing 4 KiB bound and descriptor-bound
write/sync custody. HTTPS text projections name the condition and action. Keep
PagerDuty's derived dedup key, Events API projection, response-class refusal,
redaction, bounded one-attempt outcomes and explicit network enablement unchanged.
A local or HTTPS condition page does not gain PagerDuty's safe resubmission:
resubmit remains limited to retained PagerDuty records. Historical inspection
must describe the actual transport, and unresolved local failures remain scoped
to their condition even through the retained directory-binding wrapper.

Alternatives: adding fields to v1 would weaken its exact compatibility boundary;
a new v3 envelope would duplicate an already sufficient strict contract. Reusing
v2 is the bounded choice. No new transport, dynamic handler system, broadcast,
production route, credential, store schema or monitoring profile is introduced.
The Attention producer and ordinary site integration follow separately; this
change must not pretend their existing v1 copy became condition-bound.

The proof uses native CLI delivery and inspection, actual file/store custody,
transport-boundary tests, negative controls for unauthorized tuples, duplicate
and failure behavior, and the existing workspace suite. Shared literal vectors
pin the common envelope for the future Attention consumer. A finite test matrix
and prose suffice: no unbounded delivery, human receipt or exactly-once claim is
made, and provider-specific retry authority remains unchanged.
