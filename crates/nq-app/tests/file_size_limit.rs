//! Process-level qualification of file-limit refusal and store recovery.

use std::process::Command;

#[test]
fn file_limit_returns_an_error_and_preserves_the_store() {
    let result = Command::new("python3")
        .arg("-c")
        .arg(
            r#"
import pathlib, resource, signal, sqlite3, subprocess, sys, tempfile

nq, nqd = sys.argv[1:]
def limited():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512, 512))
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)

with tempfile.TemporaryDirectory(prefix='nq-file-limit-') as root:
    root = pathlib.Path(root)
    config, database = root / 'nq.toml', root / 'state' / 'nq.db'
    config.write_text(f'''schema = "nq.config.v1"
database_path = "{database}"
socket_path = "{root}/run/nq.sock"
admissions_dir = "{root}/admissions"
helper_runtime_dir = "{root}/run/helpers"
''')
    def run(*args, **kwargs):
        return subprocess.run(args, capture_output=True, text=True, timeout=20, **kwargs)
    initialized = run(nq, '--config', str(config), '--json', 'init')
    assert initialized.returncode == 0, initialized.stderr
    def inspect():
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as db:
            assert db.execute('pragma integrity_check').fetchall() == [('ok',)]
            return db.execute('select count(*) from status_events').fetchone()[0]
    before = inspect()
    for _ in range(3):
        refused = run(nqd, '--config', str(config), '--once', preexec_fn=limited)
        assert refused.returncode > 0, (refused.returncode, refused.stderr)
        assert inspect() == before
    control = run(nqd, '--config', str(config), '--once')
    assert control.returncode == 0, control.stderr
    assert inspect() > before

    # This deliberately unguarded write proves that the child limit and
    # default signal disposition actually terminate a writer in this fixture.
    negative = run(sys.executable, '-c',
        'import os,sys,signal; signal.signal(signal.SIGXFSZ,signal.SIG_DFL); f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600); '
        'os.write(f,b"x"*512); os.write(f,b"x")',
        str(root / 'negative'), preexec_fn=limited)
    assert negative.returncode == -signal.SIGXFSZ, negative.returncode
"#,
        )
        .arg(env!("CARGO_BIN_EXE_nq"))
        .arg(env!("CARGO_BIN_EXE_nqd"))
        .output()
        .expect("run local file-limit fixture");
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
