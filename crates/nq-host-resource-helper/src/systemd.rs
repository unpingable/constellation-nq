//! `nq.systemd_unit/v2` branch: the system manager's machine identity and
//! one unit's load, active and sub state, read over the local system bus.
//!
//! Read-only: `org.freedesktop.DBus.Hello` (required by the bus before any
//! other call), `org.freedesktop.DBus.Peer.GetMachineId` and
//! `org.freedesktop.systemd1.Manager.ListUnitsByNames`, nothing else, each
//! sent with `NO_AUTO_START`. The last loads an unloaded unit into manager
//! memory exactly as `systemctl show` does; no unit is started, stopped,
//! reloaded, or given a job. Every inability to answer is a typed
//! `SystemdUnitFailureCode`; an unexpected unit state is an observation,
//! never a failure.
//!
//! The exchange is one blocking Unix stream whose reads and writes carry
//! socket timeouts from a budget that ends before the request deadline (the
//! caller keeps a report margin). `connect` to the local bus socket is the
//! one step without a timeout: it returns immediately unless the bus's
//! listen backlog is full, and NQ's own exchange deadline still bounds it. It creates no thread and no async runtime: the
//! helper runs under `RLIMIT_NPROC`, which a thread-spawning bus library
//! cannot satisfy when the execution account already runs many processes.
//! The wire subset is fixed (EXTERNAL authentication, three method calls,
//! two reply signatures) and parsed strictly; it is not a general D-Bus
//! client.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

use nq_profiles::systemd_unit_v2::{self, SystemdUnitFailureCode, SystemdUnitScope};

use crate::{CollectionFailure, ResourceSource};

const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
const BUS_SERVICE: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";
/// Signature of one `ListUnitsByNames` reply: name, description, load,
/// active, sub, following, unit path, job id, job type, job path.
const UNIT_LIST_SIGNATURE: &str = "a(ssssssouso)";
/// Bound on any one received message.
const MAX_MESSAGE_BYTES: usize = 1 << 16;
/// Bound on unrelated messages (for example `NameAcquired`) skipped while
/// waiting for one reply.
const MAX_SKIPPED_MESSAGES: usize = 16;
/// Bound on rows accepted from one `ListUnitsByNames` reply.
const MAX_UNIT_ROWS: usize = 16;
const NO_AUTO_START: u8 = 0x2;
const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

type Failure = CollectionFailure<SystemdUnitFailureCode>;

/// One row as the manager returned it, before any interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerUnitRow {
    /// The unit's canonical name as the manager reports it.
    pub name: String,
    /// `LoadState`.
    pub load_state: String,
    /// `ActiveState`.
    pub active_state: String,
    /// `SubState`.
    pub sub_state: String,
    /// `Following`: empty unless the unit follows another.
    pub following: String,
}

/// The manager's answer to one query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerUnitReply {
    /// The manager's machine identity.
    pub machine_id: String,
    /// Every row `ListUnitsByNames` returned for the one requested name.
    pub rows: Vec<ManagerUnitRow>,
}

/// Validated systemd unit observation ready for the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdUnitObservation {
    /// `LoadState`, inside the systemd 255 vocabulary.
    pub load_state: String,
    /// `ActiveState`, inside the systemd 255 vocabulary.
    pub active_state: String,
    /// `SubState`, a bounded token.
    pub sub_state: String,
}

/// Read-only systemd unit observation: the manager's machine identity, then
/// exactly one row for exactly the requested canonical name, inside the
/// closed state vocabularies.
///
/// # Errors
///
/// Returns a typed [`CollectionFailure`] when the manager could not answer,
/// answered for another machine or another unit, or answered outside the
/// admitted vocabulary.
pub fn observe_systemd_unit(
    scope: &SystemdUnitScope,
    source: &impl ResourceSource,
    budget: Duration,
) -> Result<SystemdUnitObservation, CollectionFailure<SystemdUnitFailureCode>> {
    if budget.is_zero() {
        return Err(CollectionFailure::new(
            SystemdUnitFailureCode::QueryTimeout,
            "no request time remained for the manager query",
            true,
        ));
    }
    let reply = source.systemd_unit(&scope.unit_name, budget)?;
    if reply.machine_id != scope.machine_id {
        return Err(CollectionFailure::new(
            SystemdUnitFailureCode::MachineIdentityMismatch,
            "the system manager's machine identity differs from the exact request scope",
            false,
        ));
    }
    let [row] = reply.rows.as_slice() else {
        return Err(CollectionFailure::new(
            SystemdUnitFailureCode::UnitListCardinality,
            "the system manager did not return exactly one unit row",
            false,
        ));
    };
    if row.name != scope.unit_name || !row.following.is_empty() {
        return Err(CollectionFailure::new(
            SystemdUnitFailureCode::UnitNameNotCanonical,
            "the requested name resolves to another unit (an alias or a followed unit)",
            false,
        ));
    }
    if !systemd_unit_v2::LOAD_STATES.contains(&row.load_state.as_str())
        || !systemd_unit_v2::ACTIVE_STATES.contains(&row.active_state.as_str())
        || !systemd_unit_v2::valid_sub_state(&row.sub_state)
    {
        return Err(CollectionFailure::new(
            SystemdUnitFailureCode::UnitStateUnrecognized,
            "the reported unit state is outside the admitted systemd 255 vocabulary",
            false,
        ));
    }
    Ok(SystemdUnitObservation {
        load_state: row.load_state.clone(),
        active_state: row.active_state.clone(),
        sub_state: row.sub_state.clone(),
    })
}

/// Query the local system manager; every read and write after `connect` is
/// bounded by `budget`.
pub(crate) fn query_system_manager(
    unit_name: &str,
    budget: Duration,
) -> Result<ManagerUnitReply, Failure> {
    query_bus(Path::new(SYSTEM_BUS_SOCKET), unit_name, budget)
}

fn query_bus(
    socket: &Path,
    unit_name: &str,
    budget: Duration,
) -> Result<ManagerUnitReply, Failure> {
    let mut bus = Bus::connect(socket, Instant::now() + budget)?;
    bus.authenticate(nix::unistd::geteuid().as_raw())?;
    let hello = bus.call(BUS_SERVICE, BUS_PATH, BUS_SERVICE, "Hello", None)?;
    let _unique_name = single_string(&hello)?;
    let machine = bus.call(
        SYSTEMD_SERVICE,
        MANAGER_PATH,
        PEER_INTERFACE,
        "GetMachineId",
        None,
    )?;
    let machine_id = single_string(&machine)?;
    let mut body = Encoder::default();
    let length_at = body.reserve_u32();
    let elements = body.len();
    body.put_string(unit_name);
    body.patch_u32(length_at, body.len() - elements)?;
    let units = bus.call(
        SYSTEMD_SERVICE,
        MANAGER_PATH,
        MANAGER_INTERFACE,
        "ListUnitsByNames",
        Some(("as", body.into_bytes())),
    )?;
    Ok(ManagerUnitReply {
        machine_id,
        rows: unit_rows(&units)?,
    })
}

fn failure(code: SystemdUnitFailureCode, message: impl Into<String>, retriable: bool) -> Failure {
    CollectionFailure::new(code, message, retriable)
}

fn malformed(message: impl Into<String>) -> Failure {
    failure(SystemdUnitFailureCode::ReplyMalformed, message, false)
}

fn io_failure(error: &io::Error) -> Failure {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => failure(
            SystemdUnitFailureCode::QueryTimeout,
            "the system bus exchange exceeded the request deadline",
            true,
        ),
        _ => failure(
            SystemdUnitFailureCode::QueryFailed,
            format!("the system bus exchange failed: {error}"),
            true,
        ),
    }
}

/// One method reply: its body signature and body bytes (which begin on an
/// 8-byte boundary of the message, so alignment within the body is exact).
struct Reply {
    signature: String,
    body: Vec<u8>,
}

struct Bus {
    stream: UnixStream,
    deadline: Instant,
    serial: u32,
}

impl Bus {
    fn connect(socket: &Path, deadline: Instant) -> Result<Self, Failure> {
        let stream = UnixStream::connect(socket).map_err(|error| {
            failure(
                SystemdUnitFailureCode::SystemBusUnavailable,
                format!("system bus connection failed: {error}"),
                true,
            )
        })?;
        Ok(Self {
            stream,
            deadline,
            serial: 0,
        })
    }

    fn remaining(&self) -> Result<Duration, Failure> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure(
                SystemdUnitFailureCode::QueryTimeout,
                "the system bus exchange exceeded the request deadline",
                true,
            ));
        }
        Ok(remaining)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let remaining = self.remaining()?;
        self.stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| io_failure(&error))?;
        self.stream
            .write_all(bytes)
            .map_err(|error| io_failure(&error))
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), Failure> {
        let mut filled = 0;
        while filled < bytes.len() {
            let remaining = self.remaining()?;
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|error| io_failure(&error))?;
            match self.stream.read(&mut bytes[filled..]) {
                Ok(0) => {
                    return Err(failure(
                        SystemdUnitFailureCode::QueryFailed,
                        "the system bus closed the connection",
                        true,
                    ));
                }
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_failure(&error)),
            }
        }
        Ok(())
    }

    /// SASL EXTERNAL with the process's own uid, then `BEGIN`.
    fn authenticate(&mut self, uid: u32) -> Result<(), Failure> {
        let hex = uid
            .to_string()
            .bytes()
            .fold(String::new(), |mut hex, byte| {
                hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
                hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
                hex
            });
        self.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
        let mut line = Vec::with_capacity(64);
        while !line.ends_with(b"\r\n") {
            if line.len() >= 512 {
                return Err(malformed("the bus authentication reply exceeds its bound"));
            }
            let mut byte = [0_u8; 1];
            self.read_exact(&mut byte)?;
            line.push(byte[0]);
        }
        if !line.starts_with(b"OK ") {
            return Err(failure(
                SystemdUnitFailureCode::SystemBusUnavailable,
                "the system bus refused EXTERNAL authentication",
                true,
            ));
        }
        self.write_all(b"BEGIN\r\n")
    }

    fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<Reply, Failure> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or_else(|| malformed("serial exhausted"))?;
        let serial = self.serial;
        let message = method_call(serial, destination, path, interface, member, body)?;
        self.write_all(&message)?;
        for _ in 0..=MAX_SKIPPED_MESSAGES {
            let received = self.read_message()?;
            let header = parse_header(&received)?;
            if header.reply_serial != Some(serial)
                || !matches!(header.message_type, METHOD_RETURN | ERROR)
            {
                continue;
            }
            if header.message_type == ERROR {
                let name = header.error_name.unwrap_or_default();
                let code = if destination == BUS_SERVICE {
                    SystemdUnitFailureCode::SystemBusUnavailable
                } else if name == "org.freedesktop.DBus.Error.ServiceUnknown"
                    || name == "org.freedesktop.DBus.Error.NameHasNoOwner"
                {
                    SystemdUnitFailureCode::ManagerUnavailable
                } else {
                    SystemdUnitFailureCode::QueryFailed
                };
                return Err(failure(
                    code,
                    format!("{member} returned the bus error {name}"),
                    true,
                ));
            }
            return Ok(Reply {
                signature: header.signature,
                body: received[header.body_start..].to_vec(),
            });
        }
        Err(failure(
            SystemdUnitFailureCode::QueryFailed,
            "no reply arrived within the bound on unrelated messages",
            true,
        ))
    }

    fn read_message(&mut self) -> Result<Vec<u8>, Failure> {
        let mut fixed = [0_u8; 16];
        self.read_exact(&mut fixed)?;
        let total = message_length(&fixed)?;
        let mut message = vec![0_u8; total];
        message[..16].copy_from_slice(&fixed);
        self.read_exact(&mut message[16..])?;
        Ok(message)
    }
}

/// Total message length from the fixed 16-byte prefix, bounded.
fn message_length(fixed: &[u8; 16]) -> Result<usize, Failure> {
    if fixed[0] != b'l' || fixed[3] != 1 {
        return Err(malformed(
            "the reply is not a little-endian version 1 message",
        ));
    }
    let body = u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]) as usize;
    let fields = u32::from_le_bytes([fixed[12], fixed[13], fixed[14], fixed[15]]) as usize;
    let total = align(16 + fields, 8)
        .checked_add(body)
        .filter(|total| *total <= MAX_MESSAGE_BYTES)
        .ok_or_else(|| malformed("the reply exceeds its bound"))?;
    Ok(total)
}

const fn align(offset: usize, to: usize) -> usize {
    offset.div_ceil(to) * to
}

struct Header {
    message_type: u8,
    reply_serial: Option<u32>,
    error_name: Option<String>,
    signature: String,
    body_start: usize,
}

fn parse_header(message: &[u8]) -> Result<Header, Failure> {
    let fields = u32::from_le_bytes([message[12], message[13], message[14], message[15]]) as usize;
    let fields_end = 16 + fields;
    let body_start = align(fields_end, 8);
    let mut reader = Decoder::new(&message[..fields_end]);
    reader.position = 16;
    let mut header = Header {
        message_type: message[1],
        reply_serial: None,
        error_name: None,
        signature: String::new(),
        body_start,
    };
    while reader.position < fields_end {
        reader.align(8)?;
        let code = reader.byte()?;
        let signature = reader.signature()?;
        match (code, signature.as_str()) {
            (4, "s") => header.error_name = Some(reader.string()?),
            (5, "u") => header.reply_serial = Some(reader.u32()?),
            (8, "g") => header.signature = reader.signature()?,
            (_, "s" | "o") => {
                reader.string()?;
            }
            (_, "u") => {
                reader.u32()?;
            }
            (_, "g") => {
                reader.signature()?;
            }
            _ => return Err(malformed("the reply carries an unexpected header field")),
        }
    }
    reader.finish()?;
    if message[fields_end..body_start]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(malformed("the reply header padding is not zero"));
    }
    Ok(header)
}

fn method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    body: Option<(&str, Vec<u8>)>,
) -> Result<Vec<u8>, Failure> {
    let (signature, body) = body.unwrap_or(("", Vec::new()));
    let mut message = Encoder::default();
    message
        .bytes
        .extend_from_slice(&[b'l', METHOD_CALL, NO_AUTO_START, 1]);
    message.put_u32(u32::try_from(body.len()).map_err(|_| malformed("body bound"))?);
    message.put_u32(serial);
    let fields_at = message.reserve_u32();
    for (code, kind, value) in [
        (1_u8, "o", path),
        (2, "s", interface),
        (3, "s", member),
        (6, "s", destination),
    ] {
        message.align(8);
        message.bytes.push(code);
        message.put_signature(kind);
        message.put_string(value);
    }
    if !signature.is_empty() {
        message.align(8);
        message.bytes.push(8);
        message.put_signature("g");
        message.put_signature(signature);
    }
    message.patch_u32(fields_at, message.len() - 16)?;
    message.align(8);
    message.bytes.extend_from_slice(&body);
    Ok(message.into_bytes())
}

fn single_string(reply: &Reply) -> Result<String, Failure> {
    if reply.signature != "s" {
        return Err(malformed("the reply signature is not s"));
    }
    let mut reader = Decoder::new(&reply.body);
    let value = reader.string()?;
    reader.finish()?;
    Ok(value)
}

fn unit_rows(reply: &Reply) -> Result<Vec<ManagerUnitRow>, Failure> {
    if reply.signature != UNIT_LIST_SIGNATURE {
        return Err(malformed(
            "the ListUnitsByNames reply signature is not a(ssssssouso)",
        ));
    }
    let mut reader = Decoder::new(&reply.body);
    let length = reader.u32()? as usize;
    reader.align(8)?;
    let end = reader
        .position
        .checked_add(length)
        .filter(|end| *end <= reply.body.len())
        .ok_or_else(|| malformed("the unit array overruns the reply"))?;
    let mut rows = Vec::new();
    while reader.position < end {
        if rows.len() == MAX_UNIT_ROWS {
            return Err(malformed("the unit array exceeds its bound"));
        }
        reader.align(8)?;
        let name = reader.string()?;
        let _description = reader.string()?;
        let load_state = reader.string()?;
        let active_state = reader.string()?;
        let sub_state = reader.string()?;
        let following = reader.string()?;
        let _unit_path = reader.string()?;
        let _job_id = reader.u32()?;
        let _job_type = reader.string()?;
        let _job_path = reader.string()?;
        rows.push(ManagerUnitRow {
            name,
            load_state,
            active_state,
            sub_state,
            following,
        });
    }
    if reader.position != end {
        return Err(malformed("the unit array length is inconsistent"));
    }
    reader.finish()?;
    Ok(rows)
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn align(&mut self, to: usize) {
        self.bytes.resize(align(self.bytes.len(), to), 0);
    }

    fn put_u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn reserve_u32(&mut self) -> usize {
        self.put_u32(0);
        self.bytes.len() - 4
    }

    fn patch_u32(&mut self, at: usize, value: usize) -> Result<(), Failure> {
        let value = u32::try_from(value).map_err(|_| malformed("length bound"))?;
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn put_string(&mut self, value: &str) {
        self.put_u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }

    fn put_signature(&mut self, value: &str) {
        self.bytes
            .push(u8::try_from(value.len()).unwrap_or(u8::MAX));
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Strict little-endian reader: padding must be zero, strings must be
/// NUL-terminated UTF-8 without interior NUL, and every read is bounded.
struct Decoder<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| malformed("the reply is truncated"))?;
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn align(&mut self, to: usize) -> Result<(), Failure> {
        let padding = align(self.position, to) - self.position;
        if self.take(padding)?.iter().any(|byte| *byte != 0) {
            return Err(malformed("the reply padding is not zero"));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, Failure> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Failure> {
        self.align(4)?;
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn text(&mut self, length: usize) -> Result<String, Failure> {
        let bytes = self.take(length)?;
        if self.take(1)? != [0] || bytes.contains(&0) {
            return Err(malformed("a reply string is not NUL-terminated"));
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| malformed("a reply string is not UTF-8"))
    }

    fn string(&mut self) -> Result<String, Failure> {
        let length = self.u32()? as usize;
        self.text(length)
    }

    fn signature(&mut self) -> Result<String, Failure> {
        let length = usize::from(self.byte()?);
        self.text(length)
    }

    fn finish(&self) -> Result<(), Failure> {
        if self.position != self.data.len() {
            return Err(malformed("the reply carries trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        os::unix::net::UnixListener,
        thread,
    };

    /// A method return (or error) for `serial`, built with the same encoder.
    fn reply(
        message_type: u8,
        serial: u32,
        signature: &str,
        body: &[u8],
        error: Option<&str>,
    ) -> Vec<u8> {
        let mut message = Encoder::default();
        message.bytes.extend_from_slice(&[b'l', message_type, 0, 1]);
        message.put_u32(u32::try_from(body.len()).unwrap());
        message.put_u32(1_000 + serial);
        let fields_at = message.reserve_u32();
        message.align(8);
        message.bytes.push(5);
        message.put_signature("u");
        message.put_u32(serial);
        if let Some(name) = error {
            message.align(8);
            message.bytes.push(4);
            message.put_signature("s");
            message.put_string(name);
        }
        if !signature.is_empty() {
            message.align(8);
            message.bytes.push(8);
            message.put_signature("g");
            message.put_signature(signature);
        }
        let fields = message.len() - 16;
        message.patch_u32(fields_at, fields).unwrap();
        message.align(8);
        message.bytes.extend_from_slice(body);
        message.into_bytes()
    }

    fn string_body(value: &str) -> Vec<u8> {
        let mut body = Encoder::default();
        body.put_string(value);
        body.into_bytes()
    }

    fn rows_body(rows: &[[&str; 6]]) -> Vec<u8> {
        let mut body = Encoder::default();
        let length_at = body.reserve_u32();
        body.align(8);
        let start = body.len();
        for [name, load, active, sub, following, description] in rows {
            body.align(8);
            for value in [name, description, load, active, sub, following] {
                body.put_string(value);
            }
            body.put_string("/org/freedesktop/systemd1/unit/x");
            body.put_u32(0);
            body.put_string("");
            body.put_string("/");
        }
        let length = body.len() - start;
        body.patch_u32(length_at, length).unwrap();
        body.into_bytes()
    }

    #[derive(Clone)]
    enum Step {
        Reply(Vec<u8>),
        Signal,
        Silence,
    }

    /// A scripted bus on a private socket: EXTERNAL `OK`, then for each of
    /// the three calls the scripted steps, keyed by the call's serial.
    fn fake_bus(
        auth: &'static str,
        script: Vec<Vec<Step>>,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            assert!(line.starts_with(b"\0AUTH EXTERNAL "));
            writer.write_all(auth.as_bytes()).unwrap();
            if !auth.starts_with("OK ") {
                return;
            }
            line.clear();
            reader.read_until(b'\n', &mut line).unwrap();
            assert_eq!(line, b"BEGIN\r\n");
            for steps in script {
                let mut fixed = [0_u8; 16];
                if reader.read_exact(&mut fixed).is_err() {
                    return;
                }
                assert_eq!(
                    fixed[2], NO_AUTO_START,
                    "every call is sent without activation"
                );
                let mut rest = vec![0_u8; message_length(&fixed).unwrap() - 16];
                reader.read_exact(&mut rest).unwrap();
                for step in steps {
                    match step {
                        Step::Reply(bytes) => writer.write_all(&bytes).unwrap(),
                        Step::Signal => writer
                            .write_all(&reply(4, 0, "s", &string_body(":1.1"), None))
                            .unwrap(),
                        Step::Silence => {
                            thread::sleep(Duration::from_millis(400));
                            return;
                        }
                    }
                }
            }
        });
        (directory, path)
    }

    fn happy(rows: &[u8]) -> Vec<Vec<Step>> {
        vec![
            vec![
                Step::Signal,
                Step::Reply(reply(2, 1, "s", &string_body(":1.42"), None)),
            ],
            vec![Step::Reply(reply(
                2,
                2,
                "s",
                &string_body("1a5b08928e884e73bf4f60a3c73ef497"),
                None,
            ))],
            vec![
                Step::Signal,
                Step::Reply(reply(2, 3, UNIT_LIST_SIGNATURE, rows, None)),
            ],
        ]
    }

    fn query(
        auth: &'static str,
        script: Vec<Vec<Step>>,
        budget: Duration,
    ) -> Result<ManagerUnitReply, Failure> {
        let (_directory, path) = fake_bus(auth, script);
        query_bus(&path, "cron.service", budget)
    }

    fn code(result: Result<ManagerUnitReply, Failure>) -> (SystemdUnitFailureCode, bool) {
        let failure = result.expect_err("typed failure");
        (failure.code(), failure.retriable())
    }

    #[test]
    fn a_scripted_bus_answers_and_unrelated_messages_are_skipped() {
        let reply = query(
            "OK 0123456789abcdef\r\n",
            happy(&rows_body(&[[
                "cron.service",
                "loaded",
                "active",
                "running",
                "",
                "Regular background program processing daemon",
            ]])),
            Duration::from_secs(5),
        )
        .expect("answer");
        assert_eq!(reply.machine_id, "1a5b08928e884e73bf4f60a3c73ef497");
        assert_eq!(
            reply.rows,
            vec![ManagerUnitRow {
                name: "cron.service".to_owned(),
                load_state: "loaded".to_owned(),
                active_state: "active".to_owned(),
                sub_state: "running".to_owned(),
                following: String::new(),
            }]
        );
        let empty =
            query("OK 0\r\n", happy(&rows_body(&[])), Duration::from_secs(5)).expect("answer");
        assert!(empty.rows.is_empty(), "cardinality is judged by the caller");
    }

    #[test]
    fn refusals_errors_and_silence_are_typed() {
        assert_eq!(
            code(query(
                "REJECTED EXTERNAL\r\n",
                Vec::new(),
                Duration::from_secs(5)
            )),
            (SystemdUnitFailureCode::SystemBusUnavailable, true)
        );
        let mut unknown = happy(&rows_body(&[]));
        unknown[1] = vec![Step::Reply(reply(
            3,
            2,
            "s",
            &string_body("no"),
            Some("org.freedesktop.DBus.Error.ServiceUnknown"),
        ))];
        assert_eq!(
            code(query("OK 0\r\n", unknown, Duration::from_secs(5))),
            (SystemdUnitFailureCode::ManagerUnavailable, true)
        );
        let mut denied = happy(&rows_body(&[]));
        denied[2] = vec![Step::Reply(reply(
            3,
            3,
            "s",
            &string_body("no"),
            Some("org.freedesktop.DBus.Error.AccessDenied"),
        ))];
        assert_eq!(
            code(query("OK 0\r\n", denied, Duration::from_secs(5))),
            (SystemdUnitFailureCode::QueryFailed, true)
        );
        let mut silent = happy(&rows_body(&[]));
        silent[2] = vec![Step::Silence];
        assert_eq!(
            code(query("OK 0\r\n", silent, Duration::from_millis(200))),
            (SystemdUnitFailureCode::QueryTimeout, true)
        );
        let missing = tempfile::tempdir().unwrap();
        assert_eq!(
            code(query_bus(
                &missing.path().join("absent"),
                "cron.service",
                Duration::from_secs(1)
            )),
            (SystemdUnitFailureCode::SystemBusUnavailable, true)
        );
    }

    #[test]
    fn malformed_replies_are_refused_not_interpreted() {
        let mut wrong_signature = happy(&rows_body(&[]));
        wrong_signature[1] = vec![Step::Reply(reply(2, 2, "u", &7_u32.to_le_bytes(), None))];
        let mut trailing = happy(&rows_body(&[]));
        let mut body = string_body("1a5b08928e884e73bf4f60a3c73ef497");
        body.extend_from_slice(&[0, 0, 0, 0]);
        trailing[1] = vec![Step::Reply(reply(2, 2, "s", &body, None))];
        let mut unterminated = happy(&rows_body(&[]));
        let mut body = string_body("abc");
        let last = body.len() - 1;
        body[last] = b'x';
        unterminated[1] = vec![Step::Reply(reply(2, 2, "s", &body, None))];
        let mut overrun = happy(&rows_body(&[]));
        let mut rows = rows_body(&[["cron.service", "loaded", "active", "running", "", "d"]]);
        rows[0] = rows[0].wrapping_add(8);
        overrun[2] = vec![Step::Reply(reply(2, 3, UNIT_LIST_SIGNATURE, &rows, None))];
        let mut nonzero_padding = happy(&rows_body(&[]));
        let mut rows = rows_body(&[["cron.service", "loaded", "active", "running", "", "d"]]);
        rows[4] = 1;
        nonzero_padding[2] = vec![Step::Reply(reply(2, 3, UNIT_LIST_SIGNATURE, &rows, None))];
        for script in [
            wrong_signature,
            trailing,
            unterminated,
            overrun,
            nonzero_padding,
        ] {
            assert_eq!(
                code(query("OK 0\r\n", script, Duration::from_secs(5))),
                (SystemdUnitFailureCode::ReplyMalformed, false)
            );
        }
        let big_endian = [b'B', 2, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert!(message_length(&big_endian).is_err());
        let mut oversized = [b'l', 2, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        oversized[4..8].copy_from_slice(&u32::try_from(MAX_MESSAGE_BYTES).unwrap().to_le_bytes());
        assert!(message_length(&oversized).is_err());
    }

    #[test]
    fn the_call_encoding_is_the_documented_wire_form() {
        let mut body = Encoder::default();
        let at = body.reserve_u32();
        body.put_string("cron.service");
        body.patch_u32(at, body.len() - 4).unwrap();
        let message = method_call(
            3,
            SYSTEMD_SERVICE,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "ListUnitsByNames",
            Some(("as", body.into_bytes())),
        )
        .unwrap();
        assert_eq!(&message[..4], &[b'l', 1, NO_AUTO_START, 1]);
        assert_eq!(u32::from_le_bytes(message[8..12].try_into().unwrap()), 3);
        let total = message_length(&message[..16].try_into().unwrap()).unwrap();
        assert_eq!(total, message.len());
        let header = parse_header(&message).unwrap();
        assert_eq!(header.signature, "as");
        assert_eq!(header.message_type, METHOD_CALL);
        // Body: array byte length 17 (u32 12 + "cron.service" + NUL), then the string.
        let body = &message[header.body_start..];
        assert_eq!(&body[..4], &17_u32.to_le_bytes());
        assert_eq!(&body[4..8], &12_u32.to_le_bytes());
        assert_eq!(&body[8..20], b"cron.service");
        assert_eq!(body[20], 0);
        assert_eq!(body.len(), 21);
    }
}
