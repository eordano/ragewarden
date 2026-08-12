use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stanza {
    pub tag: String,

    pub args: Vec<String>,

    pub body: Vec<u8>,
}
