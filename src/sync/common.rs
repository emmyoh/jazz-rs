use crate::{
    covalue::{covaluepriority::CoValuePriority, header::CoValueHeader, session::Transaction},
    id::{rawcoid::RawCoID, session_id::SessionID},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoValueKnownState {
    pub(crate) id: RawCoID,
    /// Whether or not the header is known.
    pub(crate) header: bool,
    /// A list of sessions with their respective IDs and number of known transactions.
    pub(crate) sessions: Vec<(SessionID, usize)>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionNewContent {
    after: usize,
    new_transactions: Vec<Transaction>,
    last_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all_fields = "camelCase")]
#[serde(tag = "action")]
pub enum SyncMessage {
    #[serde(rename = "load")]
    /// Message indicating the intent to load a [`CoValue`].
    LoadMessage {
        #[serde(flatten)]
        known_state: CoValueKnownState,
    },
    #[serde(rename = "known")]
    /// Message sent after a [`SyncMessage::LoadMessage`] summarising the known state of the [`CoValue`].
    KnownStateMessage {
        /// When retrieving a [`CoValue`] where the header (thus, group) is unknown, the server replies with [`SyncMessage::KnownStateMessage`]s
        /// and [`SyncMessage::NewContentMessage`]s of the group.\
        /// The `as_dependency_of` field signifies the group is a dependency of the [`CoValue`] being loaded, to clarify the relationship between the two.
        as_dependency_of: Option<RawCoID>,
        /// If some [`SyncMessage::NewContentMessage`]s in a series fail to reach the server from a client, the server can inform the client it should correct its
        /// understanding of the server's state and resend the missing content.
        is_correction: Option<bool>,
        #[serde(flatten)]
        known_state: CoValueKnownState,
    },
    #[serde(rename = "content")]
    /// Reply to a peer's known state message with new content.\
    /// [`SyncMessage::NewContentMessage`] may be chunked into multiple messages and streamed to the peer; ie, there is no guarantee that one [`SyncMessage::KnownStateMessage`] will yield only one [`SyncMessage::NewContentMessage`].
    NewContentMessage {
        id: RawCoID,
        /// [`CoValueHeader`] to reply with if the header is not known to the peer.
        header: Option<CoValueHeader>,
        priority: CoValuePriority,
        /// A list of sessions with their respective IDs and new content.
        new: Vec<(String, SessionNewContent)>,
    },
    #[serde(rename = "done")]
    /// Signals that a client is unsubscribing to changes made to a [`CoValue`].
    DoneMessage { id: RawCoID },
}
