use super::inputs::{Inputs, MultisigData};

pub struct Program;

impl Program {
    pub fn run(inputs: &Inputs) {
        let data = MultisigData::from(&inputs.current_data);
        let verified_signers = data.verify_signatures(&inputs.new_key, &inputs.signatures);
        assert!(
            verified_signers.len() >= data.threshold.into(),
            "Threshold not met"
        );
    }
}
