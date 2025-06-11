use super::common::{CoValueUniqueness, Ruleset};
use crate::{crypto::short_hash::ShortHash, id::rawcoid::RawCoID};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoValueHeader {
    #[serde(rename = "type")]
    type_: String,
    #[serde(flatten)]
    ruleset: Ruleset,
    pub(crate) meta: Option<serde_json::Value>,
    #[serde(flatten)]
    uniqueness: CoValueUniqueness,
}

impl CoValueHeader {
    pub fn id(&self) -> Result<RawCoID> {
        Ok(RawCoID::from(ShortHash::new(serde_json::to_value(self)?)))
    }
}
