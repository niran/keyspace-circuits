#![no_main]
sp1_zkvm::entrypoint!(main);

use k_lib::ecdsa_account::{Circuit, Inputs};

pub fn main() {
    let inputs = sp1_zkvm::io::read::<Inputs>();
    sp1_zkvm::io::commit(inputs.to_commit());

    Circuit::run(&inputs)
}
