use nq_profiles::repository_state::*;
use nq_protocol::sha256_bytes;

fn evidence() -> RepositoryEvidence {
    let subject = RepositorySubject {
        worktree: "/fixture/repo".into(),
        device: 1,
        inode: 2,
        git_directory: "/fixture/repo/.git".into(),
    };
    let head = format!("{}\n", "a".repeat(40));
    RepositoryEvidence {
        subject_identity: subject.identity().unwrap(),
        subject,
        started_at: "2026-09-08T12:00:00Z".parse().unwrap(),
        ended_at: "2026-09-08T12:00:01Z".parse().unwrap(),
        git_executable: sha256_bytes(b"git"),
        collector_executable: sha256_bytes(b"collector"),
        index_snapshot: None,
        exclude_snapshot: None,
        configuration: "nq.isolated_git_configuration.rebuilt_index.v2".into(),
        commands: OPERATIONS
            .into_iter()
            .zip([
                b"false\n".to_vec(),
                head.as_bytes().to_vec(),
                vec![],
                vec![],
                head.into_bytes(),
                vec![],
                b"/fixture/repo\n".to_vec(),
                vec![],
                vec![],
                vec![],
            ])
            .map(|(operation, stdout)| CommandObservation {
                operation: operation.into(),
                exit_code: Some(0),
                stdout,
                failure: None,
            })
            .collect(),
    }
}

#[test]
fn clean_and_changed_are_replayed_not_merely_trusted() {
    let original = RepositoryExecution::produce(evidence()).unwrap();
    original
        .replay(&original.evidence.collector_executable)
        .unwrap();
    assert!(matches!(
        original.disposition,
        RepositoryDisposition::Clean { .. }
    ));
    let mut dirty = evidence();
    dirty.commands[3].stdout = b"?? new-file\0".to_vec();
    let mut changed = RepositoryExecution::produce(dirty).unwrap();
    assert!(matches!(
        changed.disposition,
        RepositoryDisposition::ChangesPresent { .. }
    ));
    changed.disposition = original.disposition;
    assert!(
        changed
            .replay(&changed.evidence.collector_executable)
            .is_err()
    );
}

#[test]
fn failed_collection_submodules_and_changing_head_never_establish_clean() {
    for index in 0..OPERATIONS.len() {
        let mut e = evidence();
        e.commands[index].exit_code = None;
        assert!(matches!(
            evaluate(&e).unwrap(),
            RepositoryDisposition::NotEstablished { .. }
        ));
    }
    let mut e = evidence();
    e.commands[2].stdout = format!("160000 {} 0\tchild\0", "b".repeat(40)).into_bytes();
    e.commands[9].stdout = e.commands[2].stdout.clone();
    assert_eq!(
        evaluate(&e).unwrap(),
        RepositoryDisposition::NotEstablished {
            reason: "submodules_unsupported".into()
        }
    );
    e = evidence();
    e.commands[4].stdout = format!("{}\n", "b".repeat(40)).into_bytes();
    assert_eq!(
        evaluate(&e).unwrap(),
        RepositoryDisposition::NotEstablished {
            reason: "head_changed_during_observation".into()
        }
    );
}

#[test]
fn malformed_subject_time_status_and_replay_identity_are_rejected() {
    let mut mismatched = evidence();
    mismatched.commands[9].stdout = b"extra staged entry".to_vec();
    assert!(evaluate(&mismatched).is_err());
    let mut e = evidence();
    e.subject.inode += 1;
    assert!(evaluate(&e).is_err());
    e = evidence();
    e.ended_at = e.started_at - chrono::Duration::seconds(1);
    assert!(evaluate(&e).is_err());
    for status in [
        b"?? truncated".as_slice(),
        b"R  target\0",
        b"!! ignored\0",
        b"XX file\0",
    ] {
        e = evidence();
        e.commands[3].stdout = status.to_vec();
        assert!(evaluate(&e).is_err());
    }
    let e = RepositoryExecution::produce(evidence()).unwrap();
    assert!(e.replay(&sha256_bytes(b"replacement")).is_err());
    let mut wrong = e.clone();
    wrong.evaluator_source = "changed".into();
    assert!(wrong.replay(&e.evidence.collector_executable).is_err());
}
