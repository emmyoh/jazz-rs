use crate::crypto::sign::Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignerID(VerifyingKey);
impl SignerID {
    pub fn new(verifying_key: impl Into<VerifyingKey>) -> Self {
        SignerID(verifying_key.into())
    }
    pub fn verify(
        &self,
        message: impl Into<serde_json::value::Value>,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        let message_string = format!("{:#}", message.into());
        Ok(self
            .0
            .verify(message_string.as_bytes(), &signature.into())?)
    }
}

impl FromStr for SignerID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("signer_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().map(|x| x.as_slice().try_into().ok().map(|y| Self(y))).ok().flatten()
        }).ok_or(anyhow::anyhow!("String not a valid signer ID; signer IDs begin with `signer_z` followed by a Base58-encoded verifying key"))
    }
}

impl Display for SignerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signer_z{}",
            bs58::encode(&self.0.as_bytes()).into_string()
        )
    }
}

impl From<VerifyingKey> for SignerID {
    fn from(verifying_key: VerifyingKey) -> Self {
        Self(verifying_key)
    }
}

impl From<&VerifyingKey> for SignerID {
    fn from(verifying_key: &VerifyingKey) -> Self {
        Self(verifying_key.clone())
    }
}
