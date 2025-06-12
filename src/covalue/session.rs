use crate::covalue::common::MAX_RECOMMENDED_TX_SIZE;
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
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;
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
    signature_after: Vec<Option<Signature>>,
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
        id: &RawCoID,
        header: &CoValueHeader,
        sessions: &DashMap<SessionID, SessionLog>,
    ) -> Self {
        Self {
            id: id.clone(),
            header: header.clone(),
            sessions: sessions.clone(),
            cached_known_state: None,
            cached_new_content_since_empty: None,
        }
    }

    pub fn expected_new_hash_after(
        &self,
        session_id: &SessionID,
        new_transactions: &Vec<Transaction>,
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

    fn do_add_transactions(
        &mut self,
        session_id: &SessionID,
        new_transactions: &Vec<Transaction>,
        new_signature: &Signature,
        expected_new_hash: &Hash,
        new_streaming_hash: &StreamingHash,
    ) {
        let mut transactions: Vec<_> = self
            .sessions
            .get(session_id)
            .map(|x| x.transactions.clone())
            .unwrap_or_default();
        transactions.append(&mut new_transactions.clone());
        let mut signature_after = self
            .sessions
            .get(session_id)
            .map(|x| x.signature_after.clone())
            .unwrap_or_default();
        let last_inbetween_signature_idx = signature_after
            .iter()
            .enumerate()
            .max_by_key(|x| x.0)
            .map(|x| x.0)
            .unwrap_or_default();
        let size_of_txs_since_last_inbetween_signature = transactions.as_slice()
            [last_inbetween_signature_idx + 1..]
            .iter()
            .fold(0, |sum, tx| {
                sum + match tx.type_.clone() {
                    TransactionType::Private {
                        key_used,
                        encrypted_changes,
                    } => encrypted_changes.len(),
                    TransactionType::Trusting { changes } => changes.len(),
                }
            });
        if size_of_txs_since_last_inbetween_signature > MAX_RECOMMENDED_TX_SIZE {
            signature_after[transactions.len() - 1] = Some(new_signature.clone());
        }
        self.sessions.insert(
            session_id.clone(),
            SessionLog {
                transactions: transactions,
                last_hash: Some(*expected_new_hash),
                streaming_hash: new_streaming_hash.clone(),
                signature_after: signature_after,
                last_signature: *new_signature,
            },
        );
        self.cached_new_content_since_empty = None;
        self.cached_known_state = None;
    }

    pub fn known_state(&mut self) -> CoValueKnownState {
        match &self.cached_known_state {
            Some(cached_known_state) => cached_known_state.clone(),
            None => {
                let known_state = self.known_state_uncached();
                self.cached_known_state.replace(known_state.clone());
                known_state
            }
        }
    }

    pub fn known_state_uncached(&self) -> CoValueKnownState {
        let sessions = self
            .sessions
            .par_iter()
            .map(|x| {
                let (id, session) = x.pair();
                (id.clone(), session.transactions.len())
            })
            .collect();
        CoValueKnownState {
            id: self.id.clone(),
            header: true,
            sessions: sessions,
        }
    }

    pub fn get_known_signature_idx(
        log: &SessionLog,
        known_state_for_session_id: &Option<usize>,
        sent_state_for_session_id: &Option<usize>,
    ) -> Option<usize> {
        let mut signature_after_keys: Vec<_> = log
            .signature_after
            .iter()
            .enumerate()
            .map(|x| x.0)
            .collect();
        signature_after_keys.par_sort_unstable_by(|a, b| a.cmp(&b));
        signature_after_keys
            .iter()
            .find(|idx| {
                **idx
                    >= (sent_state_for_session_id
                        .unwrap_or(known_state_for_session_id.unwrap_or_default()))
            })
            .map(|x| *x)
    }
}
