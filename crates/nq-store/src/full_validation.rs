//! Full validation of one WAL snapshot, with short guarded publication.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::{
    HistoryFrontier, Refusal, RetentionReport, SemanticCertification, Store, StoreError,
    StoreIdentity, ValidationWatermark, capacity, history_scope, now_utc, operation_timing,
};

/// A full snapshot's result. A missing watermark means it could not certify
/// the current store (for example, a writer committed during the scan).
pub struct FullValidation<T> {
    pub value: T,
    pub watermark: Option<ValidationWatermark>,
    pub prior_certification: &'static str,
    /// The retention report from the same snapshot as the validated history.
    pub retention: RetentionReport,
}

impl Store {
    /// Validate and certify one complete read snapshot without holding the
    /// operation guard during history scans. `validate` must apply the engine's
    /// full semantic/provider/diagnostic rules and return its certification.
    /// It runs query-only. `recover` runs after the read transaction ends and
    /// returns whether all required successor completions were recorded.
    ///
    /// Publication is conservative: any database commit during the scan or
    /// recovery leaves the sidecar unchanged and returns no watermark. Foreign
    /// sidecars and replaced database paths refuse. A held WAL reader can
    /// still cause a writer's existing capacity/checkpoint admission to refuse.
    /// Non-WAL bootstrap retains serialized validation before WAL conversion.
    pub fn validate_full_snapshot<T, E>(
        path: impl AsRef<Path>,
        engine_rules: &str,
        validate: impl FnOnce(&Self) -> Result<(T, SemanticCertification), E>,
        recover: impl FnOnce(&Self) -> Result<bool, E>,
    ) -> Result<FullValidation<T>, E>
    where
        E: From<StoreError>,
    {
        Self::full_snapshot_inner(path.as_ref(), engine_rules, validate, recover)
    }

    fn full_snapshot_inner<T, E>(
        path: &Path,
        engine_rules: &str,
        validate: impl FnOnce(&Self) -> Result<(T, SemanticCertification), E>,
        recover: impl FnOnce(&Self) -> Result<bool, E>,
    ) -> Result<FullValidation<T>, E>
    where
        E: From<StoreError>,
    {
        let bootstrap_timing = operation_timing::PhaseTiming::start("full_validation.bootstrap");
        let (mut store, file_identity) = Self::prepare_writable(path, None).map_err(E::from)?;
        drop(bootstrap_timing);
        let (value, semantic, frontier, identity, retention, prior_certification, version, changes) = {
            let setup_timing =
                operation_timing::PhaseTiming::start("full_validation.snapshot_setup");
            let guard = capacity::operation_guard(path).map_err(E::from)?;
            require_file_identity(path, file_identity).map_err(E::from)?;
            let version = data_version(&store.connection).map_err(E::from)?;
            let changes = store.connection.total_changes();
            store
                .connection
                .pragma_update(None, "query_only", true)
                .map_err(StoreError::from)
                .map_err(E::from)?;
            let snapshot =
                Transaction::new_unchecked(&store.connection, TransactionBehavior::Deferred)
                    .map_err(StoreError::from)
                    .map_err(E::from)?;
            // Establish the SQLite view before reading its sidecar under the
            // same guard used by every governed watermark publisher.
            HistoryFrontier::capture_bounds(&snapshot).map_err(E::from)?;
            let sidecar = history_scope::read_sidecar(path);
            drop(guard);
            drop(setup_timing);
            let _read_timing =
                operation_timing::PhaseTiming::start("full_validation.snapshot_read");

            store.validation = store
                .inspect_open_validation(true, sidecar)
                .map_err(E::from)?;
            let (value, semantic) = validate(&store)?;
            let bounds = store.validation.open_frontier.as_ref().ok_or_else(|| {
                E::from(StoreError::Invariant("full snapshot lacks bounds".into()))
            })?;
            // Full chains and prior-covered content comparisons are expensive;
            // they belong to this read snapshot, never the publication guard.
            let frontier = HistoryFrontier::certify(
                &snapshot,
                None,
                bounds,
                store.validation.prior.as_deref(),
            )
            .map_err(E::from)?;
            let identity = store.store_identity().map_err(E::from)?;
            let retention = store.retention_report().map_err(E::from)?;
            let prior = store.prior_certification();
            drop(snapshot);
            (
                value, semantic, frontier, identity, retention, prior, version, changes,
            )
        };
        // Refuse a replacement already observed during the read phase before
        // enabling application recovery writes. Publication checks again.
        require_file_identity(path, file_identity).map_err(E::from)?;
        store
            .connection
            .pragma_update(None, "query_only", false)
            .map_err(StoreError::from)
            .map_err(E::from)?;
        store.validation.may_record = true;
        let recovered = recover(&store)?;
        let watermark = store
            .publish_full_snapshot(
                path,
                file_identity,
                version,
                changes,
                identity.as_ref(),
                recovered,
                engine_rules,
                frontier,
                semantic,
            )
            .map_err(E::from)?;
        Ok(FullValidation {
            value,
            watermark,
            prior_certification,
            retention,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_full_snapshot(
        &self,
        path: &Path,
        file_identity: (u64, u64),
        version: i64,
        changes: u64,
        identity: Option<&StoreIdentity>,
        recovered: bool,
        engine_rules: &str,
        frontier: HistoryFrontier,
        semantic: SemanticCertification,
    ) -> Result<Option<ValidationWatermark>, StoreError> {
        let publication_timing =
            operation_timing::PhaseTiming::start("full_validation.publication");
        require_file_identity(path, file_identity)?;
        let unchanged = self.connection.total_changes() == changes
            && data_version(&self.connection)? == version;
        publication_timing.value("database_unchanged", i64::from(unchanged));
        if !recovered || !unchanged {
            // This proof already cannot certify the current database. No
            // writer admission is needed to decline publication, but path
            // and foreign-sidecar refusal still apply. Nothing is written.
            let current = self.store_identity()?;
            if let history_scope::SidecarState::Present(sidecar) = history_scope::read_sidecar(path)
            {
                history_scope::refuse_foreign(path, &sidecar, current.as_ref())?;
            }
            return Ok(None);
        }
        let _guard = self.serialization_guard().map_err(|error| match error {
            error @ StoreError::Refused(Refusal::Contention(_)) => {
                StoreError::WatermarkWrite(error.to_string())
            }
            other => other,
        })?;
        require_file_identity(path, file_identity)?;
        // Exclude SQLite writers too while the short proof checks and sidecar
        // publication run; no history scans or checkpoint take place here.
        let _publication =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current = self.store_identity()?;
        if let history_scope::SidecarState::Present(sidecar) = history_scope::read_sidecar(path) {
            history_scope::refuse_foreign(path, &sidecar, current.as_ref())?;
        }
        let Some(identity) = identity else {
            return Ok(None);
        };
        if !recovered
            || current.as_ref() != Some(identity)
            || self.connection.total_changes() != changes
            || data_version(&self.connection)? != version
        {
            return Ok(None);
        }
        let written = history_scope::write_watermark(
            path,
            identity,
            engine_rules,
            frontier,
            semantic,
            now_utc(),
        )?;
        Ok(Some(written))
    }
}

fn data_version(connection: &Connection) -> Result<i64, StoreError> {
    Ok(connection.query_row("PRAGMA data_version", [], |row| row.get(0))?)
}

fn require_file_identity(path: &Path, expected: (u64, u64)) -> Result<(), StoreError> {
    let metadata = std::fs::metadata(path)?;
    if (metadata.dev(), metadata.ino()) != expected {
        return Err(StoreError::Invariant(
            "database path changed during full validation".into(),
        ));
    }
    Ok(())
}
