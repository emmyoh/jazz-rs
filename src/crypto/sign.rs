use ed25519_dalek::Signer;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);
impl Signature {
    pub fn new(signature: impl Into<ed25519_dalek::Signature>) -> Self {
        Self(signature.into())
    }
}

impl FromStr for Signature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("signature_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().map(|x| x.as_slice().try_into().ok().map(|y| Self(y))).ok().flatten()
        }).ok_or(anyhow::anyhow!("String not a valid signature; signatures begin with `signature_z` followed by a Base58-encoded Ed25519 signature"))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signature_z{}",
            bs58::encode(&self.0.to_bytes()).into_string()
        )
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(signature: ed25519_dalek::Signature) -> Self {
        Self(signature)
    }
}

impl From<&ed25519_dalek::Signature> for Signature {
    fn from(signature: &ed25519_dalek::Signature) -> Self {
        Self(signature.clone())
    }
}

impl From<&Signature> for ed25519_dalek::Signature {
    fn from(signature: &Signature) -> ed25519_dalek::Signature {
        signature.0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignerSecret(SigningKey);
impl SignerSecret {
    pub fn new(signing_key: impl Into<SigningKey>) -> Self {
        Self(signing_key.into())
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
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
    pub fn sign(&self, message: impl Into<serde_json::value::Value>) -> ed25519_dalek::Signature {
        let message_string = format!("{:#}", message.into());
        self.0.sign(message_string.as_bytes())
    }
}

impl FromStr for SignerSecret {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("signerSecret_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().map(|x| x.as_slice().try_into().ok().map(|y| Self(y))).ok().flatten()
        }).ok_or(anyhow::anyhow!("String not a valid signer secret; signer secrets begin with `signerSecret_z` followed by a Base58-encoded signing key"))
    }
}

impl Display for SignerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signerSecret_z{}",
            bs58::encode(&self.0.as_bytes()).into_string()
        )
    }
}

impl From<SigningKey> for SignerSecret {
    fn from(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl From<&SigningKey> for SignerSecret {
    fn from(signing_key: &SigningKey) -> Self {
        Self(signing_key.clone())
    }
}

impl From<&SignerSecret> for VerifyingKey {
    fn from(signing_secret: &SignerSecret) -> VerifyingKey {
        signing_secret.verifying_key()
    }
}
