//! CSH-10 pass control: lawful, public-API fork-fence usage — acquisition,
//! same-process verification, and the public construct/verify pair — proving
//! `v2-csh-10.rs` fails only at the private-field boundary and not because
//! the harness or imports are broken.

use nq_helper_sandbox::{
    C2ForkFence, construct_sg_wu_02_fence_shared_process_global_fork_fence_primitive,
    verify_sg_wu_02_fence_shared_process_global_fork_fence_primitive,
};

fn main() {
    let fence = construct_sg_wu_02_fence_shared_process_global_fork_fence_primitive();
    verify_sg_wu_02_fence_shared_process_global_fork_fence_primitive(&fence)
        .expect("public fence verification");
    let guard = C2ForkFence::acquire().expect("public fence acquisition");
    guard.verify_same_process().expect("same process");
}
