use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all_fields = "camelCase")]
pub enum AccountRole {
    Reader,
    Writer,
    Admin,
    WriteOnly,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all_fields = "camelCase")]
pub enum Role {
    Account {
        #[serde(flatten)]
        role: AccountRole,
    },
    Revoked,
    AdminInvite,
    WriterInvite,
    ReaderInvite,
    WriteOnlyInvite,
}
