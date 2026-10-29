//! Opt-in operational timings, separate from evidence and validation verdicts.
use std::io::{self, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(1);
static WINDOW: OnceLock<Instant> = OnceLock::new();
const WINDOW_DURATION: Duration = Duration::from_secs(1800);

/// A bounded, inclusive phase observation. A finish record is not success.
#[doc(hidden)]
pub struct PhaseTiming {
    phase: &'static str,
    active: Option<(u64, Instant)>,
}

fn record(writer: &mut impl Write, id: u64, phase: &str, event: &str, elapsed: u128) {
    // A closed journal/stderr must never turn a successful store operation
    // into a panic or replace its original error.
    let line = format!(
        "nq_phase pid={} id={id} phase={phase} event={event} elapsed_ns={elapsed}\n",
        std::process::id()
    );
    let _ = writer.write_all(line.as_bytes());
}

impl PhaseTiming {
    /// Enabled only by the exact operator opt-in; disabled avoids the clock.
    pub fn start(phase: &'static str) -> Self {
        let active = if std::env::var_os("NQ_DIAGNOSTIC_PHASE_TIMING").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            if WINDOW.get_or_init(Instant::now).elapsed() >= WINDOW_DURATION {
                return Self {
                    phase,
                    active: None,
                };
            }
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let start = Instant::now();
            record(&mut io::stderr().lock(), id, phase, "start", 0);
            Some((id, start))
        } else {
            None
        };
        Self { phase, active }
    }

    /// Log only an already computed numeric result, never an extra scan.
    pub fn value(&self, name: &'static str, value: i64) {
        if let Some((id, _)) = self.active {
            let line = format!(
                "nq_phase pid={} id={id} phase={} event=value name={name} value={value}\n",
                std::process::id(),
                self.phase
            );
            let _ = io::stderr().lock().write_all(line.as_bytes());
        }
    }
}

impl Drop for PhaseTiming {
    fn drop(&mut self) {
        if let Some((id, start)) = self.active {
            record(
                &mut io::stderr().lock(),
                id,
                self.phase,
                "finish",
                start.elapsed().as_nanos(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    #[test]
    fn expired_window_stops_new_records() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operation_timing::tests::expired_window_child",
                "--ignored",
            ])
            .env("NQ_DIAGNOSTIC_PHASE_TIMING", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("nq_phase "));
    }

    #[test]
    #[ignore = "isolated environment/clock helper for expired_window_stops_new_records"]
    fn expired_window_child() {
        WINDOW
            .set(Instant::now() - WINDOW_DURATION - Duration::from_secs(1))
            .unwrap();
        assert!(PhaseTiming::start("test.expired_window").active.is_none());
    }

    #[test]
    fn phase_record_uses_one_complete_write() {
        #[derive(Default)]
        struct Sink {
            calls: usize,
            bytes: Vec<u8>,
        }
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Sink::default();
        record(&mut sink, 42, "test.phase", "finish", 123);
        assert_eq!(
            sink.calls, 1,
            "shared journal streams must not interleave formatted fragments"
        );
        assert!(sink.bytes.ends_with(b"\n") && sink.bytes.len() < 512);
    }

    #[test]
    fn diagnostic_output_failure_does_not_panic() {
        record(&mut Closed, 1, "test.phase", "finish", 42);
    }
}
