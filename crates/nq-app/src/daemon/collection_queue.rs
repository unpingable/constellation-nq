//! Finite ready-acquisition turns between pending maintenance opportunities.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
    next: u64,
    ready: BTreeSet<u64>,
    cohort: BTreeSet<u64>,
    continuation_interval: Duration,
    last_opportunity_completed: Option<Instant>,
    #[cfg(test)]
    opportunities: usize,
}

#[derive(Clone, Default)]
pub(super) struct CollectionQueue {
    state: Arc<Mutex<State>>,
}

pub(super) struct CollectionTicket {
    queue: CollectionQueue,
    id: u64,
}

impl CollectionQueue {
    pub(super) fn new(continuation_interval: Duration) -> Self {
        assert!(!continuation_interval.is_zero());
        Self {
            state: Arc::new(Mutex::new(State {
                continuation_interval,
                ..State::default()
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // The only updates are set insert/remove or replacement. Recovering
        // the bookkeeping lock lets ticket Drop remove registrations during
        // unwinding rather than panicking a second time.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn register(&self) -> CollectionTicket {
        let mut state = self.state();
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .expect("collection ticket identity exhausted");
        assert!(state.ready.insert(id));
        CollectionTicket {
            queue: self.clone(),
            id,
        }
    }

    #[cfg(test)]
    pub(super) fn ready_count(&self) -> usize {
        self.state().ready.len()
    }

    #[cfg(test)]
    pub(super) fn opportunities(&self) -> usize {
        self.state().opportunities
    }
}

impl CollectionTicket {
    /// Decide only after acquiring the daemon writer. A later nonmember may
    /// reach it before a cohort member; it must defer pending expiry too.
    /// Empty cohorts still respect spacing from the last normal completion.
    pub(super) fn should_defer_pending_expiry(&self) -> bool {
        self.should_defer_pending_expiry_at(Instant::now())
    }

    fn should_defer_pending_expiry_at(&self, now: Instant) -> bool {
        let state = self.queue.state();
        assert!(state.ready.contains(&self.id));
        !state.cohort.is_empty()
            || state.last_opportunity_completed.is_some_and(|last| {
                now.saturating_duration_since(last) < state.continuation_interval
            })
    }

    /// After an ordinary maintenance opportunity, while still holding the
    /// writer, capture the other ready requests. Later arrivals never extend
    /// this cohort. Spacing starts at completion, and deferred requests never
    /// refresh it. A panic before this call leaves the previous time unchanged.
    /// The current ticket retires before that writer is released.
    pub(super) fn finish_opportunity(&self) {
        self.finish_opportunity_at(Instant::now());
    }

    fn finish_opportunity_at(&self, completed_at: Instant) {
        let mut state = self.queue.state();
        assert!(state.ready.contains(&self.id));
        assert!(
            state.cohort.is_empty(),
            "a ready acquisition cohort still has its turn"
        );
        state.last_opportunity_completed = Some(completed_at);
        state.cohort = state
            .ready
            .iter()
            .copied()
            .filter(|id| *id != self.id)
            .collect();
        #[cfg(test)]
        {
            state.opportunities += 1;
        }
    }
}

impl Drop for CollectionTicket {
    fn drop(&mut self) {
        let mut state = self.queue.state();
        state.ready.remove(&self.id);
        state.cohort.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staggered_arrivals_defer_until_interval_from_completion_expires() {
        let interval = Duration::from_secs(30);
        let queue = CollectionQueue::new(interval);
        let completed = Instant::now();
        let first = queue.register();
        assert!(!first.should_defer_pending_expiry_at(completed));
        first.finish_opportunity_at(completed);
        drop(first);
        for second in 0..30 {
            let later = queue.register();
            assert!(later.should_defer_pending_expiry_at(completed + Duration::from_secs(second)));
            drop(later);
        }
        let next = queue.register();
        assert!(!next.should_defer_pending_expiry_at(completed + interval));
        next.finish_opportunity_at(completed + interval);
        drop(next);
        let later = queue.register();
        assert!(
            later.should_defer_pending_expiry_at(completed + interval + Duration::from_secs(29))
        );
        assert_eq!(queue.opportunities(), 2);
    }

    #[test]
    fn elapsed_interval_does_not_displace_a_captured_cohort() {
        let interval = Duration::from_secs(30);
        let queue = CollectionQueue::new(interval);
        let completed = Instant::now();
        let first = queue.register();
        let older = queue.register();
        first.finish_opportunity_at(completed);
        drop(first);
        let after_interval = completed + interval;
        let later = queue.register();
        assert!(later.should_defer_pending_expiry_at(after_interval));
        assert!(older.should_defer_pending_expiry_at(after_interval));
        drop(older);
        assert!(!later.should_defer_pending_expiry_at(after_interval));
        later.finish_opportunity_at(after_interval);
    }

    #[test]
    fn cancellation_and_unwind_do_not_postpone_the_continuation_deadline() {
        let interval = Duration::from_secs(30);
        let queue = CollectionQueue::new(interval);
        let completed = Instant::now();
        let first = queue.register();
        first.finish_opportunity_at(completed);
        drop(first);
        let cancelled = queue.register();
        assert!(cancelled.should_defer_pending_expiry_at(completed + Duration::from_secs(29)));
        drop(cancelled);
        let unwound = queue.register();
        assert!(
            std::panic::catch_unwind(move || {
                let _ticket = unwound;
                panic!("unfinished opportunity fixture");
            })
            .is_err()
        );
        let after_interval = completed + interval;
        let next = queue.register();
        assert!(!next.should_defer_pending_expiry_at(after_interval));
        drop(next); // Eligible but cancelled before completion: no new timestamp.
        assert!(
            !queue
                .register()
                .should_defer_pending_expiry_at(after_interval)
        );
        assert_eq!(queue.opportunities(), 1);
    }

    #[test]
    fn waiting_cohort_runs_before_another_maintenance_opportunity() {
        let queue = CollectionQueue::default();
        let first = queue.register();
        let second = queue.register();
        let third = queue.register();
        assert!(!first.should_defer_pending_expiry());
        first.finish_opportunity();
        drop(first);
        assert!(second.should_defer_pending_expiry());
        drop(second);
        assert!(third.should_defer_pending_expiry());
        drop(third);
        assert!(!queue.register().should_defer_pending_expiry());
    }

    #[test]
    fn later_ticket_cannot_insert_maintenance_ahead_of_older_cohort() {
        let queue = CollectionQueue::default();
        let first = queue.register();
        let older = queue.register();
        first.finish_opportunity();
        drop(first);
        let later = queue.register();
        assert!(
            later.should_defer_pending_expiry(),
            "mutex order may differ from registration order"
        );
        drop(later);
        assert!(older.should_defer_pending_expiry());
        drop(older);
        assert!(!queue.register().should_defer_pending_expiry());
    }

    #[test]
    fn continuous_arrivals_do_not_extend_the_captured_cohort() {
        let queue = CollectionQueue::default();
        let first = queue.register();
        let older = queue.register();
        first.finish_opportunity();
        drop(first);
        for _ in 0..128 {
            let later = queue.register();
            assert!(later.should_defer_pending_expiry());
            drop(later);
        }
        drop(older);
        assert!(!queue.register().should_defer_pending_expiry());
    }

    #[test]
    fn capture_is_atomic_with_concurrent_registration_and_cancellation() {
        for _ in 0..64 {
            let queue = CollectionQueue::default();
            let first = queue.register();
            let older = queue.register();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let peer_queue = queue.clone();
            let peer_barrier = barrier.clone();
            let peer = std::thread::spawn(move || {
                peer_barrier.wait();
                let later = peer_queue.register();
                drop(older);
                drop(later);
            });
            barrier.wait();
            first.finish_opportunity();
            drop(first);
            peer.join().unwrap();
            assert_eq!(queue.ready_count(), 0);
            let next = queue.register();
            assert!(
                !next.should_defer_pending_expiry(),
                "either capture ordering must retire every cancelled cohort member"
            );
            next.finish_opportunity();
            drop(next);
            assert_eq!(queue.opportunities(), 2);
        }
    }

    #[test]
    fn cancelled_or_unwound_cohort_does_not_starve_maintenance() {
        let queue = CollectionQueue::default();
        let first = queue.register();
        let cancelled = queue.register();
        let unwound = queue.register();
        first.finish_opportunity();
        drop(first);
        drop(cancelled);
        assert!(
            std::panic::catch_unwind(move || {
                let _ticket = unwound;
                panic!("bounded worker failure fixture");
            })
            .is_err()
        );
        assert!(!queue.register().should_defer_pending_expiry());
    }
}
