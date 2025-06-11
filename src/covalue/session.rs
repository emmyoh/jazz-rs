use crate::id::session_id::SessionID;
use crate::sync::common::CoValueKnownState;
use crate::sync::common::SyncMessage;
use crate::{
    covalue::header::CoValueHeader,
    crypto::{hash::Hash, streaming_hash::StreamingHash},
    id::rawcoid::RawCoID,
};
use dashmap::DashMap;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// Timestamp of the transaction.
    made_at: u64,
    #[serde(flatten)]
    type_: TransactionType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedNewHashAfter {
    expected_new_hash: Hash,
    new_streaming_hash: Arc<StreamingHash>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedState {
    id: RawCoID,
    header: CoValueHeader,
    sessions: DashMap<SessionID, SessionLog>,
    cached_known_state: Option<CoValueKnownState>,
    cached_new_content_since_empty: Option<SyncMessage>,
}

impl VerifiedState {
    pub fn new(
        id: RawCoID,
        header: CoValueHeader,
        sessions: DashMap<SessionID, SessionLog>,
    ) -> Self {
        Self {
            id: id,
            header: header,
            sessions: sessions,
            cached_known_state: None,
            cached_new_content_since_empty: None,
        }
    }

    pub fn expected_new_hash_after(
        &self,
        session_id: SessionID,
        new_transactions: Vec<Transaction>,
    ) -> anyhow::Result<ExpectedNewHashAfter> {
        let mut streaming_hash = self
            .sessions
            .get(&session_id)
            .map(|x| x.streaming_hash.clone())
            .unwrap_or_default();
        for transaction in new_transactions {
            streaming_hash.update(serde_json::to_value(transaction)?);
        }
        Ok(ExpectedNewHashAfter {
            expected_new_hash: streaming_hash.digest(),
            new_streaming_hash: Arc::new(streaming_hash),
        })
    }
}
