use crate::{
    covalue::common::RawCoValue,
    crypto::short_hash::{SHORT_HASH_LENGTH, ShortHash},
};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

use super::common::CoID;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawCoID(Vec<u8>);
impl RawCoID {
    pub fn new(bytes: Vec<u8>) -> Self {
        RawCoID(bytes)
    }
}

impl FromStr for RawCoID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("co_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().map(Self).ok()
        }).ok_or(anyhow::anyhow!("String not a valid CoID; CoIDs begin with `co_z` followed by a Base58-encoded string"))
    }
}

impl Display for RawCoID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "co_z{}",
            bs58::encode(&self.0.get(..SHORT_HASH_LENGTH).unwrap_or_default()).into_string()
        )
    }
}

impl<T: RawCoValue> From<CoID<T>> for RawCoID {
    fn from(id: CoID<T>) -> Self {
        id.0
    }
}

impl From<ShortHash> for RawCoID {
    fn from(hash: ShortHash) -> Self {
        Self(hash.0.to_vec())
    }
}
