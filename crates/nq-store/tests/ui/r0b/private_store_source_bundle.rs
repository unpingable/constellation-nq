use nq_store::{AuthenticatedPhysicalPrelaunchSources, IndependentGovernedProjectionSources};

fn main() {
    let _ = std::mem::size_of::<AuthenticatedPhysicalPrelaunchSources>();
    let _ = std::mem::size_of::<IndependentGovernedProjectionSources>();
}
