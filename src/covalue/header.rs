use super::common::{CoValueUniqueness, Ruleset};
use crate::{
    covalue::covaluepriority::CoValuePriority, crypto::short_hash::ShortHash, id::rawcoid::RawCoID,
};
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

impl From<&CoValueHeader> for CoValuePriority {
    fn from(header: &CoValueHeader) -> CoValuePriority {
        let header_meta_type = header
            .meta
            .clone()
            .map(|x| {
                x.get("type")
                    .map(|y| y.clone().as_str().map(|z| z.to_string()))
            })
            .flatten()
            .flatten()
            .unwrap_or_default();
        match (
            header.type_.as_str(),
            header_meta_type.as_str(),
            header.ruleset.clone(),
        ) {
            (_, "account", _) => CoValuePriority::High,
            (_, _, Ruleset::Group { initial_admin: _ }) => CoValuePriority::High,
            ("costream", "binary", _) => CoValuePriority::Low,
            _ => CoValuePriority::Medium,
        }
    }
}

impl From<CoValueHeader> for CoValuePriority {
    fn from(header: CoValueHeader) -> CoValuePriority {
        (&header).into()
    }
}

impl From<&Option<CoValueHeader>> for CoValuePriority {
    fn from(header: &Option<CoValueHeader>) -> CoValuePriority {
        match header {
            Some(header) => header.into(),
            None => CoValuePriority::Medium,
        }
    }
}

impl From<Option<CoValueHeader>> for CoValuePriority {
    fn from(header: Option<CoValueHeader>) -> CoValuePriority {
        (&header).into()
    }
}

impl From<bool> for CoValuePriority {
    fn from(_: bool) -> CoValuePriority {
        CoValuePriority::Medium
    }
}

impl From<&bool> for CoValuePriority {
    fn from(_: &bool) -> CoValuePriority {
        CoValuePriority::Medium
    }
}
