use crate::covalue::common::MAX_RECOMMENDED_TX_SIZE;
use crate::covalue::covaluepriority::CoValuePriority;
use crate::crypto::sign::Signature;
use crate::id::session_id::SessionID;
use crate::id::signer_id::SignerID;
use crate::sync::common::CoValueKnownState;
use crate::sync::common::SessionNewContent;
use crate::sync::common::SyncMessage;
use crate::{
    covalue::header::CoValueHeader,
    crypto::{hash::Hash, streaming_hash::StreamingHash},
    id::rawcoid::RawCoID,
};
use dashmap::DashMap;
use dashmap::DashSet;
use rayon::iter::IntoParallelIterator;
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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
    cached_new_content_since_empty: Option<Vec<SyncMessage>>,
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
                        key_used: _,
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
        known_state_for_session_id: Option<&usize>,
        sent_state_for_session_id: Option<&usize>,
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
                    >= (*sent_state_for_session_id
                        .unwrap_or(&(known_state_for_session_id.map(|x| *x)).unwrap_or_default()))
            })
            .map(|x| *x)
    }

    pub fn try_add_transactions(
        &mut self,
        session_id: &SessionID,
        signer_id: &SignerID,
        new_transactions: &Vec<Transaction>,
        given_expected_new_hash: &Option<Hash>,
        new_signature: &Signature,
        skip_verify: &Option<bool>,
        given_new_streaming_hash: &Option<StreamingHash>,
    ) -> anyhow::Result<()> {
        let skip_verify = skip_verify.unwrap_or(false);
        match (
            skip_verify,
            given_new_streaming_hash,
            given_expected_new_hash,
        ) {
            (true, Some(given_new_streaming_hash), Some(given_expected_new_hash)) => Ok(self
                .do_add_transactions(
                    session_id,
                    new_transactions,
                    new_signature,
                    given_expected_new_hash,
                    given_new_streaming_hash,
                )),
            _ => {
                let ExpectedNewHashAfter {
                    expected_new_hash,
                    new_streaming_hash,
                } = self.expected_new_hash_after(session_id, new_transactions)?;
                if let Some(given_expected_new_hash) = given_expected_new_hash {
                    if given_expected_new_hash != &expected_new_hash {
                        return Err(anyhow::anyhow!(
                            "Invalid hash for session {} does not match (expected: {given_expected_new_hash}, actual: {expected_new_hash}",
                            self.id
                        ));
                    }
                }
                signer_id.verify(expected_new_hash.to_string(), new_signature)?;
                self.do_add_transactions(
                    session_id,
                    new_transactions,
                    new_signature,
                    &expected_new_hash,
                    &*new_streaming_hash,
                );
                Ok(())
            }
        }
    }

    pub fn new_content_since(
        &mut self,
        known_state: &Option<CoValueKnownState>,
    ) -> Option<Vec<SyncMessage>> {
        let is_known_state_empty = known_state
            .as_ref()
            .map(|x| !x.header && x.sessions.is_empty())
            .unwrap_or(true);
        match (
            is_known_state_empty,
            self.cached_new_content_since_empty.as_ref(),
        ) {
            (true, Some(cached_new_content_since_empty)) => {
                return Some(cached_new_content_since_empty.clone());
            }
            _ => (),
        };

        let mut current_piece = SyncMessage::NewContentMessage {
            id: self.id.clone(),
            header: match known_state.as_ref().map(|x| x.header).unwrap_or(true) {
                true => None,
                false => Some(self.header.clone()),
            },
            priority: CoValuePriority::from(&self.header),
            new: DashMap::new(),
        };
        let mut pieces = vec![current_piece.clone()];
        let sent_state: DashMap<SessionID, usize> = DashMap::new();
        let mut piece_size = 0;
        let mut sessions_to_do_again: Option<DashSet<SessionID>> = None;
        while sessions_to_do_again.as_ref().is_none_or(|x| !x.is_empty()) {
            let sessions_to_do = (sessions_to_do_again)
                .clone()
                .unwrap_or(self.sessions.par_iter().map(|x| x.key().clone()).collect());
            for x in sessions_to_do.iter() {
                let session_id = x.key();
                let log = &(self
                    .sessions
                    .get(session_id)
                    .map(|x| x.value().clone())
                    .unwrap_or_default());
                let known_state_for_session_id = known_state
                    .as_ref()
                    .map(|x| x.sessions.get(session_id).map(|y| y.value().clone()))
                    .flatten();
                let sent_state_for_session_id =
                    sent_state.get(session_id).map(|x| x.value().clone());
                let next_known_signature_idx = Self::get_known_signature_idx(
                    log,
                    known_state_for_session_id.as_ref(),
                    sent_state_for_session_id.as_ref(),
                );

                let first_new_tx_idx =
                    sent_state_for_session_id.unwrap_or(known_state_for_session_id.unwrap_or(0));
                let after_last_new_tx_idx = next_known_signature_idx
                    .map(|x| x + 1)
                    .unwrap_or(log.transactions.len());
                let n_new_tx = usize::max(0, after_last_new_tx_idx - first_new_tx_idx);

                match (n_new_tx, &sessions_to_do_again) {
                    (0, Some(sessions_to_do_again)) => {
                        sessions_to_do_again.remove(session_id);
                        continue;
                    }
                    _ => (),
                };

                if after_last_new_tx_idx < log.transactions.len() {
                    match &sessions_to_do_again {
                        None => {
                            sessions_to_do_again = Some(DashSet::new());
                        }
                        Some(sessions_to_do_again) => {
                            sessions_to_do_again.insert(session_id.clone());
                        }
                    }
                }

                let old_piece_size = piece_size;
                for tx in log
                    .transactions
                    .iter()
                    .skip(first_new_tx_idx)
                    .take(n_new_tx)
                {
                    piece_size = piece_size
                        + match &tx.type_ {
                            TransactionType::Private {
                                key_used: _,
                                encrypted_changes,
                            } => encrypted_changes.len(),
                            TransactionType::Trusting { changes } => changes.len(),
                        }
                }

                if piece_size >= MAX_RECOMMENDED_TX_SIZE {
                    current_piece = SyncMessage::NewContentMessage {
                        id: self.id.clone(),
                        header: None,
                        priority: self.header.clone().into(),
                        new: DashMap::new(),
                    };
                    pieces.push(current_piece.clone());
                    piece_size = piece_size - old_piece_size;
                }

                let mut session_entry = match &current_piece {
                    SyncMessage::NewContentMessage {
                        id: _,
                        header: _,
                        priority: _,
                        new,
                    } => new.get(session_id).map(|x| x.value().clone()),
                    _ => None,
                };
                if let None = session_entry {
                    session_entry = Some(SessionNewContent {
                        after: sent_state_for_session_id
                            .unwrap_or(known_state_for_session_id.unwrap_or(0)),
                        new_transactions: vec![],
                        last_signature: Signature::default(),
                    });
                    match (&current_piece, &session_entry) {
                        (
                            SyncMessage::NewContentMessage {
                                id: _,
                                header: _,
                                priority: _,
                                new,
                            },
                            Some(session_entry),
                        ) => {
                            new.insert(session_id.clone(), session_entry.clone());
                        }
                        _ => (),
                    }
                }

                for tx in log
                    .transactions
                    .iter()
                    .skip(first_new_tx_idx)
                    .take(n_new_tx)
                {
                    if let Some(session_entry) = &mut session_entry {
                        session_entry.new_transactions.push(tx.clone());
                    }
                }

                if let Some(session_entry) = &mut session_entry {
                    session_entry.last_signature = match next_known_signature_idx
                        .map(|x| log.signature_after.get(x).map(|y| y.clone()))
                        .flatten()
                        .flatten()
                    {
                        None => log.last_signature,
                        Some(next_known_signature) => next_known_signature,
                    }
                }

                sent_state.insert(
                    session_id.clone(),
                    sent_state_for_session_id.unwrap_or(known_state_for_session_id.unwrap_or(0))
                        + n_new_tx,
                );
            }
        }

        let pieces_with_content: Vec<_> = pieces.into_par_iter().filter(|x| matches!(x, SyncMessage::NewContentMessage { new, .. } if !new.is_empty()) || matches!(x, SyncMessage::NewContentMessage { header, .. } if header.is_some())).collect();
        if pieces_with_content.is_empty() {
            return None;
        }

        if is_known_state_empty {
            self.cached_new_content_since_empty = Some(pieces_with_content.clone());
        }

        Some(pieces_with_content)
    }
}
