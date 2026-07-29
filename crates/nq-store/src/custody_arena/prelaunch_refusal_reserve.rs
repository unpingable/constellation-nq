//! Independently preallocated custody for failures that happen before a
//! per-execution arena exists.
//!
//! Slots are deliberately one-use in this precursor. There is no recycle API:
//! a later campaign may add one only when it consumes an exact durable
//! drain/archive acknowledgement.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};

use super::{
    ArenaError, LifetimeLockedFile, align_up, create_arena_file, ensure_arena_root,
    fallocate_exact, lock_lifetime_exclusive, normalized_database_path, open_arena_file,
    raw_digest, read_exact_at, sync_directory, verify_arena_file, verify_arena_root,
    verify_zero_range, write_all_at, write_zero_range,
};

const RESERVE_FORMAT: &str = "nq.prelaunch_refusal_reserve.v1";
const SLOT_MAGIC: &[u8; 8] = b"NQPRH001";
const SLOT_HEADER_SIZE: u64 = 4096;
const SLOT_HEADER_BYTES: usize = 4096;
const SLOT_HEADER_COUNT: u64 = 2;
const SLOT_HEADER_COPIES: usize = 2;
const SLOT_JSON_OFFSET: usize = 128;
const MAX_SLOT_JSON_BYTES: usize = 3072;
const RESERVE_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrelaunchReserveConfig {
    pub(crate) reserve_identity: Sha256Digest,
    pub(crate) slot_count: u32,
    pub(crate) receipt_capacity: u64,
}

impl PrelaunchReserveConfig {
    fn validate(&self) -> Result<(), ArenaError> {
        if self.slot_count == 0 || self.receipt_capacity == 0 {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve requires nonzero slots and capacity".into(),
            ));
        }
        if self.slot_count > 4096 {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve exceeds the bounded slot limit".into(),
            ));
        }
        Ok(())
    }

    fn slot_stride(&self) -> Result<u64, ArenaError> {
        align_up(
            SLOT_HEADER_SIZE
                .checked_mul(SLOT_HEADER_COUNT)
                .and_then(|overhead| overhead.checked_add(self.receipt_capacity))
                .ok_or_else(|| {
                    ArenaError::Invalid("prelaunch refusal slot length overflowed".into())
                })?,
            SLOT_HEADER_SIZE,
        )
    }

    fn file_length(&self) -> Result<u64, ArenaError> {
        self.slot_stride()?
            .checked_mul(u64::from(self.slot_count))
            .ok_or_else(|| ArenaError::Invalid("prelaunch refusal reserve overflowed".into()))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrelaunchSlotState {
    Available,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CommittedCarrier {
    carrier_id: Sha256Digest,
    byte_length: u64,
    bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SlotHeader {
    schema: String,
    sequence: u64,
    reserve_identity: Sha256Digest,
    slot_index: u32,
    slot_generation: u64,
    slot_count: u32,
    receipt_capacity: u64,
    state: PrelaunchSlotState,
    committed_carrier: Option<CommittedCarrier>,
}

impl SlotHeader {
    fn initial(config: &PrelaunchReserveConfig, slot_index: u32) -> Self {
        Self {
            schema: RESERVE_FORMAT.into(),
            sequence: 1,
            reserve_identity: config.reserve_identity.clone(),
            slot_index,
            slot_generation: 1,
            slot_count: config.slot_count,
            receipt_capacity: config.receipt_capacity,
            state: PrelaunchSlotState::Available,
            committed_carrier: None,
        }
    }

    fn validate(
        &self,
        config: &PrelaunchReserveConfig,
        expected_slot: u32,
    ) -> Result<(), ArenaError> {
        if self.schema != RESERVE_FORMAT
            || self.reserve_identity != config.reserve_identity
            || self.slot_index != expected_slot
            || self.slot_count != config.slot_count
            || self.receipt_capacity != config.receipt_capacity
            || self.slot_generation == 0
            || self.sequence == 0
        {
            return Err(ArenaError::Invalid(
                "prelaunch refusal slot identity or layout differs".into(),
            ));
        }
        match (self.state, &self.committed_carrier) {
            (PrelaunchSlotState::Available, None) | (PrelaunchSlotState::Committed, Some(_)) => {
                Ok(())
            }
            _ => Err(ArenaError::Invalid(
                "prelaunch refusal slot state and receipt differ".into(),
            )),
        }
    }
}

/// Exact bytes held for later refusal adjudication.
///
/// This store-internal carrier proves byte identity and custody only. It does
/// not establish that the bytes are a valid refusal, correspond to a request,
/// or came from an authorized decision path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrelaunchRefusalCarrier {
    carrier_id: Sha256Digest,
    exact_bytes: Vec<u8>,
}

impl PrelaunchRefusalCarrier {
    pub(crate) fn from_exact_bytes(exact_bytes: Vec<u8>) -> Result<Self, ArenaError> {
        if exact_bytes.is_empty() {
            return Err(ArenaError::Invalid(
                "prelaunch refusal carrier cannot be empty".into(),
            ));
        }
        Ok(Self {
            carrier_id: sha256_bytes(&exact_bytes),
            exact_bytes,
        })
    }

    pub(crate) fn carrier_id(&self) -> &Sha256Digest {
        &self.carrier_id
    }

    pub(crate) fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordedPrelaunchCarrier {
    pub(crate) slot_index: u32,
    pub(crate) slot_generation: u64,
    pub(crate) carrier_id: Sha256Digest,
    pub(crate) bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrelaunchSlotInspection {
    pub(crate) slot_index: u32,
    pub(crate) slot_generation: u64,
    pub(crate) sequence: u64,
    pub(crate) state: PrelaunchSlotState,
    pub(crate) carrier_id: Option<Sha256Digest>,
    pub(crate) recovered_torn_header: bool,
}

struct OpenSlot {
    header: SlotHeader,
    active_header: usize,
    recovered_torn_header: bool,
}

/// Bounded reserve established before per-execution arena allocation.
///
/// `record` either returns an exact durable carrier identity or an error. Once
/// a write starts, any error poisons this handle: dropping and reopening is the
/// only adjudication path. An error never implies that no bytes reached disk.
pub(crate) struct PrelaunchRefusalReserve {
    database_path: PathBuf,
    root: PathBuf,
    path: PathBuf,
    file: LifetimeLockedFile,
    config: PrelaunchReserveConfig,
    slots: Vec<OpenSlot>,
    poisoned: bool,
    #[cfg(test)]
    fail_after_payload_sync: bool,
}

impl PrelaunchRefusalReserve {
    pub(crate) fn root_for_database(database_path: &Path) -> Result<PathBuf, ArenaError> {
        let database_path = normalized_database_path(database_path)?;
        let file_name = database_path
            .file_name()
            .ok_or_else(|| ArenaError::Invalid("database path has no final component".into()))?;
        let mut reserve_name = file_name.to_os_string();
        reserve_name.push(".nq-prelaunch-refusal-v1");
        Ok(database_path.with_file_name(reserve_name))
    }

    fn relative_path(config: &PrelaunchReserveConfig) -> PathBuf {
        let digest = config
            .reserve_identity
            .as_str()
            .strip_prefix("sha256:")
            .expect("validated digest always has prefix");
        PathBuf::from(format!("{digest}.reserve"))
    }

    pub(crate) fn create(
        database_path: &Path,
        config: PrelaunchReserveConfig,
    ) -> Result<Self, ArenaError> {
        config.validate()?;
        let database_path = normalized_database_path(database_path)?;
        let root = Self::root_for_database(&database_path)?;
        ensure_arena_root(&database_path, &root)?;
        let relative = Self::relative_path(&config);
        let path = root.join(&relative);
        let file = lock_lifetime_exclusive(create_arena_file(&database_path, &root, &relative)?)?;
        fallocate_exact(&file, config.file_length()?)?;
        for slot_index in 0..config.slot_count {
            let header = SlotHeader::initial(&config, slot_index);
            write_slot_header(&file, &config, slot_index, 0, &header)?;
            write_slot_header(&file, &config, slot_index, 1, &header)?;
        }
        file.sync_all()?;
        sync_directory(&root)?;
        let mut reserve = Self {
            database_path,
            root,
            path,
            file,
            config,
            slots: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_after_payload_sync: false,
        };
        reserve.reload()?;
        Ok(reserve)
    }

    pub(crate) fn open(
        database_path: &Path,
        config: PrelaunchReserveConfig,
    ) -> Result<Self, ArenaError> {
        config.validate()?;
        let database_path = normalized_database_path(database_path)?;
        let root = Self::root_for_database(&database_path)?;
        let root_identity = verify_arena_root(&database_path, &root)?;
        let relative = Self::relative_path(&config);
        let path = root.join(&relative);
        let file = lock_lifetime_exclusive(open_arena_file(
            &database_path,
            &root,
            &relative,
            &root_identity,
        )?)?;
        let mut reserve = Self {
            database_path,
            root,
            path,
            file,
            config,
            slots: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_after_payload_sync: false,
        };
        reserve.reload()?;
        Ok(reserve)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn inspections(&self) -> Result<Vec<PrelaunchSlotInspection>, ArenaError> {
        self.ensure_usable()?;
        Ok(self
            .slots
            .iter()
            .map(|slot| PrelaunchSlotInspection {
                slot_index: slot.header.slot_index,
                slot_generation: slot.header.slot_generation,
                sequence: slot.header.sequence,
                state: slot.header.state,
                carrier_id: slot
                    .header
                    .committed_carrier
                    .as_ref()
                    .map(|receipt| receipt.carrier_id.clone()),
                recovered_torn_header: slot.recovered_torn_header,
            })
            .collect())
    }

    pub(crate) fn record(
        &mut self,
        carrier: PrelaunchRefusalCarrier,
    ) -> Result<RecordedPrelaunchCarrier, ArenaError> {
        if self.poisoned {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve has an indeterminate prior write; drop and reopen it before reuse"
                    .into(),
            ));
        }
        self.verify_file_shape()?;
        let slot_position = self
            .slots
            .iter()
            .position(|slot| slot.header.state == PrelaunchSlotState::Available)
            .ok_or_else(|| {
                ArenaError::Invalid(
                    "prelaunch refusal reserve is exhausted; receipt was not durably recorded"
                        .into(),
                )
            })?;
        let slot_index = self.slots[slot_position].header.slot_index;
        let payload_length = u64::try_from(carrier.exact_bytes.len())
            .map_err(|_| ArenaError::Invalid("prelaunch refusal length overflowed".into()))?;
        if payload_length == 0 || payload_length > self.config.receipt_capacity {
            return Err(ArenaError::Invalid(format!(
                "prelaunch refusal requires {payload_length} bytes but reserve capacity is {}",
                self.config.receipt_capacity
            )));
        }

        let payload_offset = slot_payload_offset(&self.config, slot_index)?;
        // From this point onward any error may have left scratch or a
        // committed successor. This live handle cannot safely decide which.
        self.poisoned = true;
        write_zero_range(&self.file, payload_offset, self.config.receipt_capacity)?;
        self.file.sync_data()?;
        write_all_at(&self.file, payload_offset, &carrier.exact_bytes)?;
        self.file.sync_data()?;
        #[cfg(test)]
        if self.fail_after_payload_sync {
            return Err(ArenaError::Invalid(
                "injected indeterminate prelaunch-refusal write".into(),
            ));
        }

        let bytes_digest = sha256_bytes(&carrier.exact_bytes);
        let current = self.slots[slot_position].header.clone();
        let mut next = current.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| ArenaError::Invalid("prelaunch slot sequence overflowed".into()))?;
        next.state = PrelaunchSlotState::Committed;
        next.committed_carrier = Some(CommittedCarrier {
            carrier_id: carrier.carrier_id.clone(),
            byte_length: payload_length,
            bytes_digest: bytes_digest.clone(),
        });
        validate_slot_successor(&current, &next)?;

        let target = (self.slots[slot_position].active_header + 1) % 2;
        write_slot_header(&self.file, &self.config, slot_index, target, &next)?;
        self.file.sync_data()?;
        let reopened = read_slot_header(&self.file, &self.config, slot_index, target)?;
        if reopened != next {
            return Err(ArenaError::Invalid(
                "prelaunch refusal header differed immediately after sync".into(),
            ));
        }
        let reopened_bytes = read_committed_receipt(&self.file, &self.config, &next)?
            .ok_or_else(|| ArenaError::Invalid("prelaunch refusal vanished after sync".into()))?;
        if reopened_bytes != carrier.exact_bytes {
            return Err(ArenaError::Invalid(
                "prelaunch refusal differed immediately after sync".into(),
            ));
        }
        self.slots[slot_position] = OpenSlot {
            header: next,
            active_header: target,
            recovered_torn_header: false,
        };
        self.poisoned = false;
        Ok(RecordedPrelaunchCarrier {
            slot_index,
            slot_generation: current.slot_generation,
            carrier_id: carrier.carrier_id,
            bytes_digest,
        })
    }

    pub(crate) fn committed_receipts(
        &self,
    ) -> Result<Vec<(RecordedPrelaunchCarrier, Vec<u8>)>, ArenaError> {
        self.ensure_usable()?;
        self.verify_file_shape()?;
        self.slots
            .iter()
            .filter_map(|slot| {
                let metadata = slot.header.committed_carrier.as_ref()?;
                Some(
                    read_committed_receipt(&self.file, &self.config, &slot.header).and_then(
                        |bytes| {
                            let bytes = bytes.ok_or_else(|| {
                                ArenaError::Invalid(
                                    "committed prelaunch refusal is unavailable".into(),
                                )
                            })?;
                            Ok((
                                RecordedPrelaunchCarrier {
                                    slot_index: slot.header.slot_index,
                                    slot_generation: slot.header.slot_generation,
                                    carrier_id: metadata.carrier_id.clone(),
                                    bytes_digest: metadata.bytes_digest.clone(),
                                },
                                bytes,
                            ))
                        },
                    ),
                )
            })
            .collect()
    }

    fn reload(&mut self) -> Result<(), ArenaError> {
        self.verify_file_shape()?;
        let mut slots = Vec::with_capacity(self.config.slot_count as usize);
        for slot_index in 0..self.config.slot_count {
            let first = read_slot_header(&self.file, &self.config, slot_index, 0);
            let second = read_slot_header(&self.file, &self.config, slot_index, 1);
            let (header, active_header, recovered_torn_header) = select_slot_header(first, second)?;
            header.validate(&self.config, slot_index)?;
            read_committed_receipt(&self.file, &self.config, &header)?;
            slots.push(OpenSlot {
                header,
                active_header,
                recovered_torn_header,
            });
        }
        self.slots = slots;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), ArenaError> {
        if self.poisoned {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve has an indeterminate prior write; drop and reopen it before any state read or transition"
                    .into(),
            ));
        }
        Ok(())
    }

    fn verify_file_shape(&self) -> Result<(), ArenaError> {
        verify_arena_root(&self.database_path, &self.root)?;
        verify_arena_file(&self.database_path, &self.root, &self.file)?;
        let metadata = self.file.metadata()?;
        let expected_length = self.config.file_length()?;
        if metadata.len() != expected_length {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve length differs".into(),
            ));
        }
        let allocated = metadata.blocks().checked_mul(512).ok_or_else(|| {
            ArenaError::Invalid("prelaunch refusal allocation accounting overflowed".into())
        })?;
        if allocated < expected_length {
            return Err(ArenaError::Invalid(
                "prelaunch refusal reserve is sparse or deallocated".into(),
            ));
        }
        Ok(())
    }
}

fn slot_base(config: &PrelaunchReserveConfig, slot_index: u32) -> Result<u64, ArenaError> {
    if slot_index >= config.slot_count {
        return Err(ArenaError::Invalid(
            "prelaunch refusal slot index is outside the reserve".into(),
        ));
    }
    config
        .slot_stride()?
        .checked_mul(u64::from(slot_index))
        .ok_or_else(|| ArenaError::Invalid("prelaunch refusal slot offset overflowed".into()))
}

fn slot_header_offset(
    config: &PrelaunchReserveConfig,
    slot_index: u32,
    copy: usize,
) -> Result<u64, ArenaError> {
    if copy >= SLOT_HEADER_COPIES {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header-copy index differs".into(),
        ));
    }
    slot_base(config, slot_index)?
        .checked_add(
            SLOT_HEADER_SIZE
                .checked_mul(copy as u64)
                .ok_or_else(|| ArenaError::Invalid("slot header offset overflowed".into()))?,
        )
        .ok_or_else(|| ArenaError::Invalid("slot header offset overflowed".into()))
}

fn slot_payload_offset(
    config: &PrelaunchReserveConfig,
    slot_index: u32,
) -> Result<u64, ArenaError> {
    slot_base(config, slot_index)?
        .checked_add(SLOT_HEADER_SIZE * SLOT_HEADER_COUNT)
        .ok_or_else(|| ArenaError::Invalid("prelaunch refusal payload offset overflowed".into()))
}

fn encode_slot_header(header: &SlotHeader) -> Result<[u8; SLOT_HEADER_BYTES], ArenaError> {
    let json = canonical_json_bytes(header)
        .map_err(|error| ArenaError::Invalid(format!("cannot encode refusal header: {error}")))?;
    if json.len() > MAX_SLOT_JSON_BYTES {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header exceeds its fixed bound".into(),
        ));
    }
    let mut block = [0_u8; SLOT_HEADER_BYTES];
    block[..8].copy_from_slice(SLOT_MAGIC);
    block[8] = RESERVE_VERSION;
    block[16..24].copy_from_slice(
        &u64::try_from(json.len())
            .map_err(|_| ArenaError::Invalid("refusal header length overflowed".into()))?
            .to_be_bytes(),
    );
    block[24..56].copy_from_slice(&raw_digest(&json));
    let end = SLOT_JSON_OFFSET
        .checked_add(json.len())
        .ok_or_else(|| ArenaError::Invalid("refusal header range overflowed".into()))?;
    block[SLOT_JSON_OFFSET..end].copy_from_slice(&json);
    Ok(block)
}

fn decode_slot_header(block: &[u8; SLOT_HEADER_BYTES]) -> Result<SlotHeader, ArenaError> {
    if &block[..8] != SLOT_MAGIC || block[8] != RESERVE_VERSION {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header magic or version differs".into(),
        ));
    }
    if block[9..16].iter().any(|byte| *byte != 0)
        || block[56..SLOT_JSON_OFFSET].iter().any(|byte| *byte != 0)
    {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header reserved bytes differ".into(),
        ));
    }
    let length = usize::try_from(u64::from_be_bytes(
        block[16..24].try_into().expect("fixed range"),
    ))
    .map_err(|_| ArenaError::Invalid("prelaunch refusal header length differs".into()))?;
    if length == 0 || length > MAX_SLOT_JSON_BYTES {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header length differs".into(),
        ));
    }
    let end = SLOT_JSON_OFFSET
        .checked_add(length)
        .ok_or_else(|| ArenaError::Invalid("prelaunch refusal header range overflowed".into()))?;
    if block[end..].iter().any(|byte| *byte != 0) {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header padding differs".into(),
        ));
    }
    let json = &block[SLOT_JSON_OFFSET..end];
    if raw_digest(json).as_slice() != &block[24..56] {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header digest differs".into(),
        ));
    }
    let header: SlotHeader = serde_json::from_slice(json).map_err(|error| {
        ArenaError::Invalid(format!("cannot decode prelaunch refusal header: {error}"))
    })?;
    if canonical_json_bytes(&header)
        .map_err(|error| ArenaError::Invalid(format!("cannot canonicalize header: {error}")))?
        != json
    {
        return Err(ArenaError::Invalid(
            "prelaunch refusal header is not canonical".into(),
        ));
    }
    Ok(header)
}

fn write_slot_header(
    file: &File,
    config: &PrelaunchReserveConfig,
    slot_index: u32,
    copy: usize,
    header: &SlotHeader,
) -> Result<(), ArenaError> {
    let block = encode_slot_header(header)?;
    write_all_at(file, slot_header_offset(config, slot_index, copy)?, &block)
}

fn read_slot_header(
    file: &File,
    config: &PrelaunchReserveConfig,
    slot_index: u32,
    copy: usize,
) -> Result<SlotHeader, ArenaError> {
    let mut block = [0_u8; SLOT_HEADER_BYTES];
    read_exact_at(
        file,
        slot_header_offset(config, slot_index, copy)?,
        &mut block,
    )?;
    decode_slot_header(&block)
}

fn select_slot_header(
    first: Result<SlotHeader, ArenaError>,
    second: Result<SlotHeader, ArenaError>,
) -> Result<(SlotHeader, usize, bool), ArenaError> {
    match (first, second) {
        (Ok(first), Ok(second)) if first == second => Ok((second, 1, false)),
        (Ok(first), Ok(second)) if first.sequence == second.sequence => Err(ArenaError::Invalid(
            "prelaunch refusal slot has equal-sequence split-brain headers".into(),
        )),
        (Ok(first), Ok(second)) => {
            let (older, newer, newer_index) = if first.sequence < second.sequence {
                (&first, &second, 1)
            } else {
                (&second, &first, 0)
            };
            validate_slot_successor(older, newer)?;
            Ok((newer.clone(), newer_index, false))
        }
        (Ok(header), Err(_)) => Ok((header, 0, true)),
        (Err(_), Ok(header)) => Ok((header, 1, true)),
        (Err(first), Err(second)) => Err(ArenaError::Invalid(format!(
            "both prelaunch refusal slot headers are invalid: {first}; {second}"
        ))),
    }
}

fn validate_slot_successor(previous: &SlotHeader, next: &SlotHeader) -> Result<(), ArenaError> {
    let mut expected = previous.clone();
    expected.sequence = expected
        .sequence
        .checked_add(1)
        .ok_or_else(|| ArenaError::Invalid("prelaunch slot sequence overflowed".into()))?;
    if previous.state != PrelaunchSlotState::Available
        || previous.committed_carrier.is_some()
        || next.state != PrelaunchSlotState::Committed
        || next.committed_carrier.is_none()
    {
        return Err(ArenaError::Invalid(
            "prelaunch refusal slot transition is not the one-use legal successor".into(),
        ));
    }
    expected.state = next.state;
    expected
        .committed_carrier
        .clone_from(&next.committed_carrier);
    if &expected != next {
        return Err(ArenaError::Invalid(
            "prelaunch refusal slot header is not its exact legal successor".into(),
        ));
    }
    Ok(())
}

fn read_committed_receipt(
    file: &File,
    config: &PrelaunchReserveConfig,
    header: &SlotHeader,
) -> Result<Option<Vec<u8>>, ArenaError> {
    let payload_offset = slot_payload_offset(config, header.slot_index)?;
    let Some(metadata) = &header.committed_carrier else {
        // Bytes written before a committed successor header are scratch. The
        // next record clears the entire fixed partition before reuse.
        return Ok(None);
    };
    if metadata.byte_length == 0 || metadata.byte_length > config.receipt_capacity {
        return Err(ArenaError::Invalid(
            "committed prelaunch refusal length differs".into(),
        ));
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(metadata.byte_length).map_err(|_| {
            ArenaError::Invalid("committed refusal length exceeds address space".into())
        })?
    ];
    read_exact_at(file, payload_offset, &mut bytes)?;
    if sha256_bytes(&bytes) != metadata.bytes_digest {
        return Err(ArenaError::Invalid(
            "committed prelaunch refusal digest differs".into(),
        ));
    }
    let carrier = PrelaunchRefusalCarrier::from_exact_bytes(bytes.clone())?;
    if carrier.carrier_id != metadata.carrier_id {
        return Err(ArenaError::Invalid(
            "committed prelaunch refusal carrier identity differs".into(),
        ));
    }
    verify_zero_range(
        file,
        payload_offset + metadata.byte_length,
        config.receipt_capacity - metadata.byte_length,
        "committed prelaunch-refusal padding",
    )?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    use tempfile::tempdir;

    use super::*;

    fn config(label: &str, slot_count: u32) -> PrelaunchReserveConfig {
        PrelaunchReserveConfig {
            reserve_identity: sha256_bytes(format!("reserve:{label}").as_bytes()),
            slot_count,
            receipt_capacity: 4096,
        }
    }

    fn carrier(label: &str) -> PrelaunchRefusalCarrier {
        PrelaunchRefusalCarrier::from_exact_bytes(
            format!("unvalidated refusal candidate:{label}").into_bytes(),
        )
        .expect("refusal carrier")
    }

    #[test]
    fn bounded_slots_are_durable_and_never_overwritten() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("durable", 2);
        let first = carrier("one");
        let second = carrier("two");
        let first_id = first.carrier_id().clone();
        let second_id = second.carrier_id().clone();

        let mut reserve =
            PrelaunchRefusalReserve::create(&database, config.clone()).expect("reserve");
        assert_eq!(reserve.record(first).expect("first").slot_index, 0);
        assert_eq!(reserve.record(second).expect("second").slot_index, 1);
        assert!(matches!(
            reserve.record(carrier("three")),
            Err(ArenaError::Invalid(message)) if message.contains("exhausted")
                && message.contains("not durably recorded")
        ));
        let path = reserve.path().to_owned();
        drop(reserve);

        let reopened = PrelaunchRefusalReserve::open(&database, config).expect("reopen reserve");
        assert_eq!(reopened.path(), path);
        let committed = reopened.committed_receipts().expect("committed receipts");
        assert_eq!(committed.len(), 2);
        assert_eq!(committed[0].0.carrier_id, first_id);
        assert_eq!(committed[1].0.carrier_id, second_id);
        assert!(
            reopened
                .inspections()
                .expect("inspections")
                .iter()
                .all(|slot| slot.state == PrelaunchSlotState::Committed)
        );
    }

    #[test]
    fn carrier_is_exact_byte_custody_not_refusal_semantics() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("byte-custody", 1);
        let mut reserve = PrelaunchRefusalReserve::create(&database, config).expect("reserve");
        let hostile = PrelaunchRefusalCarrier::from_exact_bytes(
            br#"{"schema":"nq.prelaunch_custody_refusal.v1","refusal_id":"invented"}"#.to_vec(),
        )
        .expect("byte carrier deliberately does not claim semantics");
        let expected = hostile.exact_bytes().to_vec();
        reserve.record(hostile).expect("exact-byte record");
        assert_eq!(
            reserve.committed_receipts().expect("receipts")[0].1,
            expected
        );
    }

    #[test]
    fn indeterminate_write_poison_requires_reopen_before_reuse() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("poison", 1);
        let mut reserve =
            PrelaunchRefusalReserve::create(&database, config.clone()).expect("reserve");
        reserve.fail_after_payload_sync = true;
        assert!(matches!(
            reserve.record(carrier("first")),
            Err(ArenaError::Invalid(message)) if message.contains("injected indeterminate")
        ));
        assert!(matches!(
            reserve.record(carrier("retry-on-stale-handle")),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        assert!(matches!(
            reserve.inspections(),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        assert!(matches!(
            reserve.committed_receipts(),
            Err(ArenaError::Invalid(message)) if message.contains("drop and reopen")
        ));
        drop(reserve);

        let mut reopened =
            PrelaunchRefusalReserve::open(&database, config).expect("reopen adjudication");
        assert_eq!(
            reopened.inspections().expect("inspections")[0].state,
            PrelaunchSlotState::Available
        );
        reopened
            .record(carrier("after-reopen"))
            .expect("record after adjudication");
    }

    #[test]
    fn one_torn_slot_header_recovers_and_two_refuse() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("torn", 1);
        let reserve = PrelaunchRefusalReserve::create(&database, config.clone()).expect("reserve");
        let path = reserve.path().to_owned();
        drop(reserve);

        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("corruptor");
        file.write_at(b"TORN", 0).expect("first corruption");
        file.sync_all().expect("sync first");
        drop(file);
        let reopened =
            PrelaunchRefusalReserve::open(&database, config.clone()).expect("one-copy recovery");
        assert!(reopened.inspections().expect("inspections")[0].recovered_torn_header);
        drop(reopened);

        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("second corruptor");
        file.write_at(b"TORN", SLOT_HEADER_SIZE)
            .expect("second corruption");
        file.sync_all().expect("sync second");
        drop(file);
        assert!(matches!(
            PrelaunchRefusalReserve::open(&database, config),
            Err(ArenaError::Invalid(message)) if message.contains("both prelaunch refusal")
        ));
    }

    #[test]
    fn hole_punch_is_refused_before_recording() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("hole", 1);
        let reserve = PrelaunchRefusalReserve::create(&database, config.clone()).expect("reserve");
        nix::fcntl::fallocate(
            reserve.file.as_raw_fd(),
            nix::fcntl::FallocateFlags::FALLOC_FL_PUNCH_HOLE
                | nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE,
            i64::try_from(slot_payload_offset(&config, 0).expect("payload offset"))
                .expect("offset"),
            i64::try_from(SLOT_HEADER_SIZE).expect("length"),
        )
        .expect("hole punch");
        reserve.file.sync_all().expect("hole sync");
        drop(reserve);
        assert!(matches!(
            PrelaunchRefusalReserve::open(&database, config),
            Err(ArenaError::Invalid(message)) if message.contains("sparse or deallocated")
        ));
    }

    #[test]
    fn exclusive_lifetime_lock_refuses_a_second_reserve_handle() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        File::create(&database).expect("database");
        let config = config("exclusive-handle", 1);
        let first =
            PrelaunchRefusalReserve::create(&database, config.clone()).expect("first reserve");

        assert!(matches!(
            PrelaunchRefusalReserve::open(&database, config.clone()),
            Err(ArenaError::Invalid(message)) if message.contains("exclusive lifetime lock")
        ));

        drop(first);
        let reopened = PrelaunchRefusalReserve::open(&database, config)
            .expect("lock releases only on handle drop");
        assert_eq!(
            reopened.inspections().expect("inspections")[0].state,
            PrelaunchSlotState::Available
        );
    }
}
