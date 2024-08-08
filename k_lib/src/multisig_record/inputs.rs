use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashSet, error::Error};

use super::{k_public_key::KPublicKey, k_signature::KSignature};

#[derive(Debug, Clone)]
pub struct CurrentData([u8; 256]);

impl Serialize for CurrentData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for CurrentData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        if bytes.len() > 256 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"expected max 256 bytes",
            ));
        }

        let mut array = [0u8; 256];
        array.copy_from_slice(bytes);
        Ok(CurrentData(array))
    }
}

impl TryFrom<&[KPublicKey]> for CurrentData {
    type Error = InputError;

    // Create CurrentData from up to 3 public keys with a default threshold of 1.
    fn try_from(value: &[KPublicKey]) -> Result<Self, Self::Error> {
        if value.len() > 3 {
            return Err(InputError);
        }
        let mut bytes = [0u8; 256];
        for (i, pk) in value.iter().enumerate() {
            bytes[i * 64..(i + 1) * 64].copy_from_slice(&pk.0);
        }
        bytes[255] = 1;
        Ok(CurrentData(bytes))
    }
}

pub trait MultisigDataGetter {
    fn get_bytes(&self) -> &[u8; 256];

    fn get_threshold(&self) -> u8 {
        let bytes = self.get_bytes();
        bytes[bytes.len() - 1]
    }
}

impl MultisigDataGetter for CurrentData {
    fn get_bytes(&self) -> &[u8; 256] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct VerifyingKeyBytes([u8; 64]);

pub struct MultisigData {
    pub owners: [VerifyingKeyBytes; 3],
    pub threshold: u8,
}

impl MultisigData {
    pub fn is_owner(&self, owner_index: u8, recovered_key: [u8; 64]) -> bool {
        assert!(
            owner_index < 3,
            "CurrentData can only fit 3 owners and a threshold"
        );
        recovered_key[..] == self.owners[usize::from(owner_index)].0
    }

    pub fn verify_signatures(
        &self,
        new_key: &[u8; 32],
        signatures: &[KSignature],
    ) -> HashSet<VerifyingKeyBytes> {
        let mut unique_signers: HashSet<VerifyingKeyBytes> = HashSet::new();
        for sig in signatures.iter() {
            let recovered_key = sig.ecrecover(new_key);
            if self.is_owner(sig.owner_index, recovered_key) {
                unique_signers.insert(VerifyingKeyBytes(recovered_key));
            }
        }
        unique_signers
    }
}

impl From<&CurrentData> for MultisigData {
    fn from(value: &CurrentData) -> Self {
        let mut owners = [VerifyingKeyBytes([0; 64]); 3];
        #[allow(clippy::needless_range_loop)]
        for i in 0..owners.len() {
            let bytes: [u8; 64] = value.0[i * 64..(i + 1) * 64]
                .try_into()
                .expect("This slice should always be 64 bytes");
            owners[i] = VerifyingKeyBytes(bytes);
        }
        let threshold = value.0[255];
        Self { owners, threshold }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Inputs {
    pub current_data: CurrentData,
    pub new_key: [u8; 32],
    pub signatures: Vec<KSignature>,
}

impl Inputs {
    pub fn new(
        signers: &[KPublicKey],
        new_key: [u8; 32],
        signatures: Vec<KSignature>,
    ) -> Result<Self, InputError> {
        let current_data: CurrentData = signers.try_into()?;
        Ok(Self {
            current_data,
            new_key,
            signatures,
        })
    }
}

#[derive(Debug, Default)]
pub struct InputError;
impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Input Error")
    }
}
impl Error for InputError {}
