//! BEDROCK one-shot node observation executable.

fn main() {
    if let Err(error) = nq_k3s_exact_occurrence::node_observation::live_main() {
        eprintln!("BEDROCK node observation refused: {error}");
        std::process::exit(1);
    }
}
