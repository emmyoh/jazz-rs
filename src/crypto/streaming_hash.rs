use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingHash {
    #[serde(skip)]
    hasher: blake3::Hasher,
}

impl StreamingHash {
    pub fn update<T: Into<serde_json::value::Value>>(&mut self, value: T) {
        let json_value = value.into();
        let json_string = format!("{:#}", json_value);
        self.hasher.update_rayon(json_string.as_bytes());
    }

    pub fn digest(&self) -> super::hash::Hash {
        super::hash::Hash(*self.hasher.finalize().as_bytes())
    }
}
