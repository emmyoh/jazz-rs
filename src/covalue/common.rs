use crate::id::{common::RawAccountID, rawcoid::RawCoID};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub enum CoValueType {
    CoMap,
    Group,
    Account,
    Profile,
    CoList,
    CoPlainText,
    CoStream,
    BinaryCoStream,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoValueUniqueness {
    uniqueness: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all_fields = "camelCase")]
#[serde(tag = "type")]
pub enum Ruleset {
    UnsafeAllowAll,
    Group { initial_admin: RawAccountID },
    OwnedByGroup { group: RawCoID },
}

pub enum SyncRole {
    Server,
    Client,
    Peer,
    Storage,
}

pub trait RawCoValue {}

pub const MAX_RECOMMENDED_TX_SIZE: usize = 100 * 1024;
