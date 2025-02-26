use crate::crypto::{hash::Hash, streaming_hash::StreamingHash};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionPrivacy {
    /// Transaction is encrypted.
    Private,
    /// Transaction is not encrypted.
    Trusting,
}

impl From<TransactionType> for TransactionPrivacy {
    fn from(type_: TransactionType) -> Self {
        match type_ {
            TransactionType::Private { .. } => TransactionPrivacy::Private,
            TransactionType::Trusting { .. } => TransactionPrivacy::Trusting,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all_fields = "camelCase")]
#[serde(tag = "privacy")]
pub enum TransactionType {
    /// Transaction is encrypted.
    Private {
        /// ID of the key used for encryption.
        key_used: Vec<u8>,
        encrypted_changes: Vec<u8>,
    },
    /// Transaction is not encrypted.
    Trusting { changes: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// Timestamp of the transaction.
    made_at: u64,
    #[serde(flatten)]
    type_: TransactionType,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SessionLog {
    pub(crate) transactions: Vec<Transaction>,
    /// Latest rolling hash of the session's transactions.
    last_hash: Option<Hash>,
    streaming_hash: StreamingHash,
    /// List of signatures after each transaction.
    signature_after: Vec<(usize, Option<Signature>)>,
    /// Latest signed hash of the session's transactions.
    last_signature: Signature,
}
