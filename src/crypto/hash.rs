use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Hash(pub(crate) [u8; blake3::OUT_LEN]);

impl Hash {
    pub fn new<T: Into<serde_json::value::Value>>(value: T) -> Self {
        let json_value = value.into();
        let json_string = format!("{:#}", json_value);
        Self(blake3::hash(json_string.as_bytes()).as_bytes().to_owned())
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("hash_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().ok().and_then(|z| z.try_into().map(Self).ok())
        }).ok_or(anyhow::anyhow!("String not a valid `Hash`; `Hash`s begin with `hash_z` followed by a Base58-encoded BLAKE3 hash"))
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hash_z{}", bs58::encode(&self.0).into_string())
    }
}
