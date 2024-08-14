use sp1_helper::build_program;

fn main() {
    build_program("../batcher");
    build_program("../ecdsa_record");
    build_program("../multisig_record");
}
