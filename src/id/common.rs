use super::{rawcoid::RawCoID, session_id::SessionID};
use crate::{covalue::common::RawCoValue, permission::account::Account};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, marker::PhantomData};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct CoID<T: RawCoValue>(pub(super) RawCoID, PhantomData<T>);
impl<T: RawCoValue> CoID<T> {
    pub fn new(id: RawCoID) -> Self {
        Self(id, PhantomData)
    }
    pub fn raw(&self) -> &RawCoID {
        &self.0
    }
}

impl<T: RawCoValue> Display for CoID<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: RawCoValue> From<RawCoID> for CoID<T> {
    fn from(id: RawCoID) -> Self {
        Self(id, PhantomData)
    }
}

pub type RawAccountID = CoID<Account>;

pub struct TransactionID {
    session_id: SessionID,
    tx_index: usize,
}
