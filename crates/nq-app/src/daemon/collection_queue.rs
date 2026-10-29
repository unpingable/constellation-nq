//! Finite ready-acquisition turns between pending maintenance opportunities.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
struct State {
    next: u64,
    ready: BTreeSet<u64>,
    cohort: BTreeSet<u64>,
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
    pub(super) fn should_defer_pending_expiry(&self) -> bool {
        let state = self.queue.state();
        assert!(state.ready.contains(&self.id));
        !state.cohort.is_empty()
    }

    /// After an ordinary maintenance opportunity, while still holding the
    /// writer, capture the other ready requests. Later arrivals never extend
    /// this cohort. The current ticket retires before that writer is released.
    pub(super) fn finish_opportunity(&self) {
        let mut state = self.queue.state();
        assert!(state.ready.contains(&self.id));
        assert!(
            state.cohort.is_empty(),
            "a ready acquisition cohort still has its turn"
        );
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
