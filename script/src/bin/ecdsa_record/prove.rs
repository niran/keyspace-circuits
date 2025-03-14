use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use sp1_sdk::{ProverClient, SP1Stdin};

use k_lib::ecdsa_record::{inputs::Inputs, k_public_key::KPublicKey, k_signature::sign_hash};

pub const ELF: &[u8] = include_bytes!("../../../../ecdsa_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    for i in 0..5 {
        let args = random_inputs();

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();
        stdin.write(&args);

        // Generate the proof.
        let proof = client
            .prove(&pk, stdin)
            .compressed()
            .run()
            .expect("failed to generate proof");
        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        let file = format!("proofs/account_proof_{i}");
        proof.save(file).expect("Failed to save proof");
    }
}

fn random_inputs() -> Inputs {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let new_key = [42; 32];
    let sig = sign_hash(&signing_key, &new_key);
    let pk = KPublicKey::from(verifying_key);

    Inputs::new(new_key, pk, sig)
}
