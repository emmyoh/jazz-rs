use std::{fmt::Display, str::FromStr};

pub const SHORT_HASH_LENGTH: usize = 19;

pub struct ShortHash(pub(crate) [u8; SHORT_HASH_LENGTH]);

impl ShortHash {
    pub fn new<T: Into<serde_json::value::Value>>(value: T) -> Self {
        let json_value = value.into();
        let json_string = format!("{:#}", json_value);
        Self(
            blake3::hash(json_string.as_bytes()).as_bytes()[..SHORT_HASH_LENGTH]
                .try_into()
                .expect("Array should have `SHORT_HASH_LENGTH` bytes"),
        )
    }
}

impl FromStr for ShortHash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        s.split_once("shortHash_z").and_then(|(_, y)| {
            bs58::decode(y).into_vec().ok().and_then(|z| z.try_into().map(Self).ok())
        }).ok_or(anyhow::anyhow!("String not a valid `ShortHash`; `ShortHash`s begin with `shortHash_z` followed by a truncated Base58-encoded BLAKE3 hash"))
    }
}

impl Display for ShortHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shortHash_z{}", bs58::encode(&self.0).into_string())
    }
}

impl From<super::hash::Hash> for ShortHash {
    fn from(hash: super::hash::Hash) -> Self {
        Self(
            hash.0[0..SHORT_HASH_LENGTH]
                .try_into()
                .expect("Array should have `SHORT_HASH_LENGTH` bytes"),
        )
    }
}
