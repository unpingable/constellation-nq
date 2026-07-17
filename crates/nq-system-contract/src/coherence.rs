//! Required-observation coherence for a published scope cut.
//!
//! A [`PublishedScopeCutV1`](crate::PublishedScopeCutV1) earns exact constituent
//! binding and custody: every source snapshot is present, ratified, and
//! digest-consistent. It does **not** by itself earn that its combined
//! assertions describe a coherent system state. `exactly_bound_cut` does not
//! imply `causally_coherent_cut`.
//!
//! This module establishes a bounded, honestly-named prerequisite: **required
//! observation coherence** under an instantaneous-snapshot model. For every
//! `Required` dependency, the provider must have been observed no later than the
//! consumer, and each consumer's transitive `Required` closure must fall inside a
//! declared observation window. That is *all* it establishes. It does **not**
//! establish actual historical existence, epoch compatibility, concurrency, or
//! causal completeness. A pass is `required_observation_v1`, never more.
//!
//! Future models may enrich observation facts and dependency relations, but may
//! not reinterpret `required_observation_v1` as establishing epochs, intervals,
//! concurrency, or historical existence.
//!
//! Consumers requiring coherent system state — and any Porter path relying on
//! that state — must refuse a raw `PublishedScopeCutV1` and require an
//! [`AdmissibleSystemCutV1`].

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DependencyRequirement, PublishedScopeCutV1, ScopeCutBodyV1, Sha256Digest,
    versioned_artifact_digest,
};

/// Schema identifier for the versioned cut-coherence witness.
pub const CUT_COHERENCE_WITNESS_SCHEMA: &str = "nq.cut_coherence_witness.v1";

/// The exact coherence claim earned by the V1 checker. Bound into every witness
/// so a future, stronger checker cannot silently upgrade an old receipt.
pub const REQUIRED_OBSERVATION_V1_CLAIM: &str = "required_observation_v1";

/// The declared coherence policy. A versioned enum, never a bag of booleans:
/// required-provider ordering is fixed V1 semantics, not a switch a witness can
/// disable. Unknown policy versions refuse.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "policy_version", rename_all = "snake_case", deny_unknown_fields)]
pub enum CutCoherencePolicy {
    /// Instant-model required-observation coherence within a window.
    RequiredObservationV1 {
        /// Maximum span of a rooted `Required` closure, in seconds.
        coherence_window_seconds: u64,
    },
}

impl CutCoherencePolicy {
    fn policy_version(&self) -> &'static str {
        match self {
            CutCoherencePolicy::RequiredObservationV1 { .. } => REQUIRED_OBSERVATION_V1_CLAIM,
        }
    }
}

/// A machine-readable refusal to admit a cut as required-observation coherent.
/// Structure is reserved for richer future models (epoch, interval, concurrency)
/// rather than flattening every failure into one string.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CutCoherenceRefusal {
    /// A `Required` provider was observed strictly later than its consumer.
    #[error("required provider {provider} was observed later than consumer {consumer}")]
    RequiredProviderObservedLate {
        /// Consumer component identity.
        consumer: String,
        /// Provider component identity.
        provider: String,
    },
    /// A consumer's transitive `Required` closure spans more than the window.
    #[error(
        "required closure rooted at {root} spans {span_seconds}s, exceeding window {window_seconds}s"
    )]
    RequiredClosureWindowExceeded {
        /// Consumer at the root of the closure.
        root: String,
        /// Observed span of the closure in seconds.
        span_seconds: i64,
        /// Declared coherence window.
        window_seconds: u64,
    },
    /// A `Required` cycle contains unequal observation instants, so no single
    /// consistent ordering exists.
    #[error("required cycle {0:?} has unequal observation instants")]
    InconsistentRequiredCycle(Vec<String>),
    /// The witness declared a coherence policy this checker does not implement.
    #[error("coherence policy {0:?} is not supported by this checker")]
    UnsupportedCoherencePolicy(String),
    /// The witness is bound to a different cut than the one presented.
    #[error("witness is bound to cut {witness}, not {cut}")]
    WitnessCutMismatch {
        /// Cut digest the witness was bound to.
        witness: String,
        /// Cut digest actually presented.
        cut: String,
    },
    /// The witness schema, claim, or digest is inconsistent with its contents.
    #[error("witness is internally inconsistent: {0}")]
    WitnessInconsistent(String),
    /// The cut cannot be evaluated (e.g. a component cites no observation).
    #[error("cut cannot be coherence-checked: {0}")]
    MalformedCut(String),
}

/// The canonical, digest-bound body of a cut-coherence witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CutCoherenceWitnessBodyV1 {
    cut_digest: Sha256Digest,
    coherence_claim: String,
    policy: CutCoherencePolicy,
}

/// A verified statement that one exact cut satisfies a declared coherence policy.
///
/// The witness binds the cut digest, the claim it earns, and the exact policy
/// (version + parameters) under a versioned schema digest. It is evidence a
/// checker produced; a consumer must still re-verify it (see
/// [`AdmissibleSystemCutV1::verify`]) rather than trust it on its face.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CutCoherenceWitnessV1 {
    /// Must be [`CUT_COHERENCE_WITNESS_SCHEMA`].
    pub schema: String,
    /// The exact cut this witness is bound to.
    pub cut_digest: Sha256Digest,
    /// The claim earned — always [`REQUIRED_OBSERVATION_V1_CLAIM`] for this type.
    pub coherence_claim: String,
    /// The exact declared policy under which coherence was established.
    pub policy: CutCoherencePolicy,
    /// Canonical digest binding the cut digest, claim, and policy.
    pub witness_digest: Sha256Digest,
}

impl CutCoherenceWitnessV1 {
    fn expected_digest(&self) -> Result<Sha256Digest, CutCoherenceRefusal> {
        let body = CutCoherenceWitnessBodyV1 {
            cut_digest: self.cut_digest.clone(),
            coherence_claim: self.coherence_claim.clone(),
            policy: self.policy.clone(),
        };
        versioned_artifact_digest(CUT_COHERENCE_WITNESS_SCHEMA, &body)
            .map_err(|error| CutCoherenceRefusal::WitnessInconsistent(error.to_string()))
    }
}

/// A cut admitted as required-observation coherent.
///
/// Constructible only by [`AdmissibleSystemCutV1::verify`], which re-runs the
/// coherence check — never by deserialization or by trusting a witness. A
/// serialized cut+witness pair is only data until it is re-verified into this
/// type, so this type carries no `Deserialize`.
#[derive(Clone, Debug)]
pub struct AdmissibleSystemCutV1 {
    cut: PublishedScopeCutV1,
    witness: CutCoherenceWitnessV1,
}

impl AdmissibleSystemCutV1 {
    /// Re-verify a cut and its witness into an admissible cut.
    ///
    /// The witness must bind this exact cut, carry the V1 schema and claim, and
    /// recompute to its own digest; then the coherence check is re-run under the
    /// witness's declared policy. The witness's assertion alone is never trusted.
    ///
    /// # Errors
    ///
    /// Returns [`CutCoherenceRefusal`] on any binding, consistency, or coherence
    /// failure.
    pub fn verify(
        cut: PublishedScopeCutV1,
        witness: CutCoherenceWitnessV1,
    ) -> Result<Self, CutCoherenceRefusal> {
        if witness.cut_digest != cut.cut_digest {
            return Err(CutCoherenceRefusal::WitnessCutMismatch {
                witness: witness.cut_digest.as_str().to_owned(),
                cut: cut.cut_digest.as_str().to_owned(),
            });
        }
        if witness.schema != CUT_COHERENCE_WITNESS_SCHEMA {
            return Err(CutCoherenceRefusal::WitnessInconsistent(format!(
                "wrong schema {:?}",
                witness.schema
            )));
        }
        if witness.coherence_claim != REQUIRED_OBSERVATION_V1_CLAIM
            || witness.coherence_claim != witness.policy.policy_version()
        {
            return Err(CutCoherenceRefusal::WitnessInconsistent(format!(
                "claim {:?} does not match policy",
                witness.coherence_claim
            )));
        }
        if witness.expected_digest()? != witness.witness_digest {
            return Err(CutCoherenceRefusal::WitnessInconsistent(
                "witness digest does not match its contents".to_owned(),
            ));
        }
        // Never trust the witness's assertion: re-run the checker.
        evaluate_cut_coherence(&cut.cut, &witness.policy)?;
        Ok(Self { cut, witness })
    }

    /// The verified cut.
    #[must_use]
    pub fn cut(&self) -> &PublishedScopeCutV1 {
        &self.cut
    }

    /// The verified witness.
    #[must_use]
    pub fn witness(&self) -> &CutCoherenceWitnessV1 {
        &self.witness
    }

    /// The exact coherence claim this admission earned.
    #[must_use]
    pub fn coherence_claim(&self) -> &str {
        &self.witness.coherence_claim
    }
}

/// Establish required-observation coherence for a cut under a policy, producing a
/// witness bound to the exact cut.
///
/// # Errors
///
/// Returns [`CutCoherenceRefusal`] if the cut is not coherent under the policy.
pub fn compute_cut_coherence_witness(
    cut: &PublishedScopeCutV1,
    policy: CutCoherencePolicy,
) -> Result<CutCoherenceWitnessV1, CutCoherenceRefusal> {
    evaluate_cut_coherence(&cut.cut, &policy)?;
    let body = CutCoherenceWitnessBodyV1 {
        cut_digest: cut.cut_digest.clone(),
        coherence_claim: REQUIRED_OBSERVATION_V1_CLAIM.to_owned(),
        policy: policy.clone(),
    };
    let witness_digest = versioned_artifact_digest(CUT_COHERENCE_WITNESS_SCHEMA, &body)
        .map_err(|error| CutCoherenceRefusal::WitnessInconsistent(error.to_string()))?;
    Ok(CutCoherenceWitnessV1 {
        schema: CUT_COHERENCE_WITNESS_SCHEMA.to_owned(),
        cut_digest: cut.cut_digest.clone(),
        coherence_claim: REQUIRED_OBSERVATION_V1_CLAIM.to_owned(),
        policy,
        witness_digest,
    })
}

/// Parse a serialized witness and re-verify it against a cut. An unknown policy
/// version refuses (fail closed) rather than being reinterpreted.
///
/// # Errors
///
/// Returns [`CutCoherenceRefusal`] on parse, binding, or coherence failure.
pub fn parse_and_verify_admissible(
    cut: PublishedScopeCutV1,
    witness_bytes: &[u8],
) -> Result<AdmissibleSystemCutV1, CutCoherenceRefusal> {
    // Fail closed on an unrecognized policy version before full parsing, so a
    // future policy is refused, never coerced into V1 semantics.
    let raw: serde_json::Value = serde_json::from_slice(witness_bytes)
        .map_err(|error| CutCoherenceRefusal::WitnessInconsistent(error.to_string()))?;
    match raw
        .get("policy")
        .and_then(|policy| policy.get("policy_version"))
    {
        Some(serde_json::Value::String(version)) if version == REQUIRED_OBSERVATION_V1_CLAIM => {}
        Some(serde_json::Value::String(version)) => {
            return Err(CutCoherenceRefusal::UnsupportedCoherencePolicy(
                version.clone(),
            ));
        }
        _ => {
            return Err(CutCoherenceRefusal::WitnessInconsistent(
                "witness has no policy version".to_owned(),
            ));
        }
    }
    let witness: CutCoherenceWitnessV1 = serde_json::from_slice(witness_bytes)
        .map_err(|error| CutCoherenceRefusal::WitnessInconsistent(error.to_string()))?;
    AdmissibleSystemCutV1::verify(cut, witness)
}

// --- Checker pipeline: (1) graph, (2) observation facts, (3) policy. A richer
// future model replaces stages 2-3 without touching cut parsing or custody. ---

/// Stage 1: the canonical directed `Required` graph, keyed by stable dependency
/// identity. `Incidental` edges do not participate in coherence.
struct RequiredEdge {
    dependency_id: String,
    consumer: String,
    provider: String,
}

fn required_edges(cut: &ScopeCutBodyV1) -> Vec<RequiredEdge> {
    let mut edges: Vec<RequiredEdge> = cut
        .dependencies
        .iter()
        .filter(|dependency| dependency.requirement == DependencyRequirement::Required)
        .map(|dependency| RequiredEdge {
            dependency_id: dependency.dependency_id.as_str().to_owned(),
            consumer: dependency.consumer_component_id.as_str().to_owned(),
            provider: dependency.provider_component_id.as_str().to_owned(),
        })
        .collect();
    edges.sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
    edges
}

/// Stage 2: each component's observation span, derived from the `captured_at` of
/// its supporting snapshots. V1 uses a point interpretation internally
/// (`captured_at -> [captured_at, captured_at]`); the span abstraction is the
/// seam a richer model consumes without publishing fake interval fields.
#[derive(Clone, Copy, Debug)]
struct ObservationSpan {
    earliest: DateTime<Utc>,
    latest: DateTime<Utc>,
}

fn observation_spans(
    cut: &ScopeCutBodyV1,
) -> Result<BTreeMap<String, ObservationSpan>, CutCoherenceRefusal> {
    let captured: BTreeMap<&str, DateTime<Utc>> = cut
        .source_snapshots
        .iter()
        .map(|snapshot| (snapshot.source_snapshot_id.as_str(), snapshot.captured_at))
        .collect();
    let mut spans = BTreeMap::new();
    for component in &cut.components {
        let mut span: Option<ObservationSpan> = None;
        for snapshot_id in &component.source_snapshot_ids {
            let captured_at = *captured.get(snapshot_id.as_str()).ok_or_else(|| {
                CutCoherenceRefusal::MalformedCut(format!(
                    "component {} cites unknown snapshot {}",
                    component.component_id.as_str(),
                    snapshot_id.as_str()
                ))
            })?;
            span = Some(match span {
                None => ObservationSpan {
                    earliest: captured_at,
                    latest: captured_at,
                },
                Some(existing) => ObservationSpan {
                    earliest: existing.earliest.min(captured_at),
                    latest: existing.latest.max(captured_at),
                },
            });
        }
        let span = span.ok_or_else(|| {
            CutCoherenceRefusal::MalformedCut(format!(
                "component {} cites no supporting snapshot",
                component.component_id.as_str()
            ))
        })?;
        spans.insert(component.component_id.as_str().to_owned(), span);
    }
    Ok(spans)
}

/// Stage 3: evaluate the declared policy over the derived graph and facts.
fn evaluate_cut_coherence(
    cut: &ScopeCutBodyV1,
    policy: &CutCoherencePolicy,
) -> Result<(), CutCoherenceRefusal> {
    let edges = required_edges(cut);
    let spans = observation_spans(cut)?;
    let span_of = |component: &str| -> Result<ObservationSpan, CutCoherenceRefusal> {
        spans.get(component).copied().ok_or_else(|| {
            CutCoherenceRefusal::MalformedCut(format!(
                "dependency references unknown component {component}"
            ))
        })
    };

    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &edges {
        adjacency
            .entry(edge.consumer.as_str())
            .or_default()
            .push(edge.provider.as_str());
    }

    match policy {
        CutCoherencePolicy::RequiredObservationV1 {
            coherence_window_seconds,
        } => {
            // A cycle whose members are not all observed at one instant admits no
            // consistent ordering; report it as a cycle, not a stray late edge.
            if let Some(cycle) = inconsistent_required_cycle(&adjacency, &spans) {
                return Err(CutCoherenceRefusal::InconsistentRequiredCycle(cycle));
            }
            // A required provider must be observed no later than its consumer.
            for edge in &edges {
                let consumer = span_of(&edge.consumer)?;
                let provider = span_of(&edge.provider)?;
                if provider.latest > consumer.latest {
                    return Err(CutCoherenceRefusal::RequiredProviderObservedLate {
                        consumer: edge.consumer.clone(),
                        provider: edge.provider.clone(),
                    });
                }
            }
            // Each consumer's transitive required closure must fit the window;
            // unrelated subgraphs are separate closures and never penalize one
            // another for the cut's total span.
            let window = i64::try_from(*coherence_window_seconds).unwrap_or(i64::MAX);
            for &root in adjacency.keys() {
                let closure = required_closure(root, &adjacency);
                let mut earliest = span_of(root)?.earliest;
                let mut latest = span_of(root)?.latest;
                for member in &closure {
                    let span = span_of(member)?;
                    earliest = earliest.min(span.earliest);
                    latest = latest.max(span.latest);
                }
                let span_seconds = (latest - earliest).num_seconds();
                if span_seconds > window {
                    return Err(CutCoherenceRefusal::RequiredClosureWindowExceeded {
                        root: root.to_owned(),
                        span_seconds,
                        window_seconds: *coherence_window_seconds,
                    });
                }
            }
            Ok(())
        }
    }
}

/// The transitive set of providers reachable from `root` via required edges,
/// including `root`.
fn required_closure(root: &str, adjacency: &BTreeMap<&str, Vec<&str>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !seen.insert(node.to_owned()) {
            continue;
        }
        if let Some(providers) = adjacency.get(node) {
            for &provider in providers {
                stack.push(provider);
            }
        }
    }
    seen
}

/// Return the members of a required cycle whose observation instants are not all
/// equal, if any such cycle exists. Uses Tarjan's strongly-connected components;
/// any component larger than one node (or a self-loop) is a cycle.
fn inconsistent_required_cycle(
    adjacency: &BTreeMap<&str, Vec<&str>>,
    spans: &BTreeMap<String, ObservationSpan>,
) -> Option<Vec<String>> {
    let mut nodes: BTreeSet<&str> = BTreeSet::new();
    for (&consumer, providers) in adjacency {
        nodes.insert(consumer);
        for &provider in providers {
            nodes.insert(provider);
        }
    }

    let mut index_counter = 0usize;
    let mut indices: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lowlink: BTreeMap<&str, usize> = BTreeMap::new();
    let mut on_stack: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut sccs: Vec<Vec<&str>> = Vec::new();

    // Iterative Tarjan to avoid recursion depth concerns.
    for &start in &nodes {
        if indices.contains_key(start) {
            continue;
        }
        let mut work: Vec<(&str, usize)> = vec![(start, 0)];
        while let Some((node, next)) = work.pop() {
            if next == 0 {
                indices.insert(node, index_counter);
                lowlink.insert(node, index_counter);
                index_counter += 1;
                stack.push(node);
                on_stack.insert(node);
            }
            let neighbors = adjacency.get(node).cloned().unwrap_or_default();
            if next < neighbors.len() {
                let neighbor = neighbors[next];
                work.push((node, next + 1));
                if !indices.contains_key(neighbor) {
                    work.push((neighbor, 0));
                } else if on_stack.contains(neighbor) {
                    let candidate = indices[neighbor];
                    let current = lowlink[node];
                    lowlink.insert(node, current.min(candidate));
                }
            } else {
                // Propagate lowlink to the parent, if any.
                if let Some(&(parent, _)) = work.last() {
                    let child = lowlink[node];
                    let parent_low = lowlink[parent];
                    lowlink.insert(parent, parent_low.min(child));
                }
                if lowlink[node] == indices[node] {
                    let mut component = Vec::new();
                    while let Some(popped) = stack.pop() {
                        on_stack.remove(popped);
                        component.push(popped);
                        if popped == node {
                            break;
                        }
                    }
                    sccs.push(component);
                }
            }
        }
    }

    for scc in sccs {
        let is_cycle = scc.len() > 1
            || scc
                .first()
                .and_then(|&node| adjacency.get(node))
                .is_some_and(|providers| providers.contains(&scc[0]));
        if !is_cycle {
            continue;
        }
        let latests: BTreeSet<DateTime<Utc>> = scc
            .iter()
            .filter_map(|node| spans.get(*node).map(|span| span.latest))
            .collect();
        if latests.len() > 1 {
            let mut members: Vec<String> = scc.iter().map(|node| (*node).to_owned()).collect();
            members.sort();
            return Some(members);
        }
    }
    None
}
