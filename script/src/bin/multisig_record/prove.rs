use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rand::Rng;
use sp1_sdk::{ProverClient, SP1Stdin};

use k_lib::multisig_record::{
    inputs::{CurrentData, Inputs},
    k_signature::sign_hash,
};

pub const ELF: &[u8] =
    include_bytes!("../../../../multisig_record/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ELF);

    for i in 0..10 {
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

        let file = format!("proofs/record_proof_{i}");
        proof.save(file).expect("failed to save proof");
    }
}

fn random_inputs() -> Inputs {
    let mut rng = rand::thread_rng();
    let num_signers = rng.gen_range(1..4);
    let signers: Vec<_> = (0..num_signers)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect();
    let new_key = rng.gen();

    let threshold = rng.gen_range(0..signers.len()) + 1;
    let signatures = signers
        .iter()
        .take(threshold)
        .enumerate()
        .map(|(owner_index, signing_key)| {
            sign_hash(signing_key, &new_key, owner_index.try_into().unwrap())
        })
        .collect();

    let pks: Vec<_> = signers
        .iter()
        .map(|signing_key| *signing_key.verifying_key())
        .collect();

    Inputs {
        current_data: CurrentData::new(pks.as_slice(), threshold.try_into().unwrap()).unwrap(),
        new_key,
        signatures,
    }
}
