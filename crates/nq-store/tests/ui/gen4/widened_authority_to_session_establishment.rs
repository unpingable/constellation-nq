use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

enum WidenedAuthority {
    C2Capacity,
    DiagnosticWarrant,
    DocketAuthority,
    EffectAuthority,
}

fn establish_from_widened_authority<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    widened: &WidenedAuthority,
) {
    let _ = session.establish_runtime_dependency_trust_root(widened);
}

fn main() {}
