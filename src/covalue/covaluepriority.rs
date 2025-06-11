use serde_repr::{Deserialize_repr, Serialize_repr};

/// The priority of a [`CoValue`] determines the priority assigned to its content messages.\
/// The priority value is used by the weighed round-robin algorithm used to determine the order in which messages are sent.
///
/// The range and order of the priority values derives from [the specification for HTTP urgency](https://www.rfc-editor.org/rfc/rfc9218.html#name-urgency).
#[derive(
    Serialize_repr, Deserialize_repr, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
#[repr(u8)]
pub enum CoValuePriority {
    /// High priority (0)
    High = 0,
    /// 1
    One = 1,
    /// 2
    Two = 2,
    /// Medium priority (3)
    Medium = 3,
    /// 4
    Four = 4,
    /// 5
    Five = 5,
    /// Low priority (6)
    Low = 6,
    /// 7
    Seven = 7,
}
