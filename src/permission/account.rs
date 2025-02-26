use crate::covalue::common::RawCoValue;
use crypto::signature::{Keypair, Signer};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Account<K: Signer<S> + Keypair = ed25519_dalek::SigningKey, S = ed25519_dalek::Signature>
{
    /// The private key of the account.
    signing_key: K,
    _s: PhantomData<S>,
}

impl RawCoValue for Account {}

impl std::hash::Hash for Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.verifying_key().hash(state)
    }
}

impl<K: Signer<S> + Keypair, S> Account<K, S> {
    /// Creates a new account with the given signing key.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The private key of the account.
    ///
    /// # Returns
    ///
    /// A new account instance.
    pub fn new(signing_key: K) -> Self {
        Self {
            signing_key,
            _s: PhantomData,
        }
    }

    /// The public key of the account.
    pub fn verifying_key(&self) -> K::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs a message with the account's private key.
    pub fn sign(&self, message: &[u8]) -> S {
        self.signing_key.sign(message)
    }
}
