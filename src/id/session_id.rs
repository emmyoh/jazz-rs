use super::{common::RawAccountID, rawcoid::RawCoID};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SessionID(pub(crate) RawAccountID, String);
impl SessionID {
    pub fn new(raw_account_id: RawAccountID, random_string: String) -> Self {
        Self(raw_account_id, random_string)
    }
}

impl FromStr for SessionID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("_session_z").and_then(|(x, y)| {
            RawCoID::from_str(x).map(|z| Self(RawAccountID::from(z), y.to_owned())).ok()
        }).ok_or(anyhow::anyhow!("String not a valid session ID; session IDs begin with a raw account ID followed by `_session_z` followed by a random string"))
    }
}

impl Display for SessionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_session_z{}", self.0, self.1)
    }
}
