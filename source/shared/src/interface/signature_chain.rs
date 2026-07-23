use {
    crate::interface::identity::{
        Identity,
        IdentityPublicKey,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ChainLink {
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ChainLink {
    pub fn serialize_content(next: IdentityPublicKey, expires: Option<u64>) -> Vec<u8> {
        return bincode::serialize(&ChainLinkContent {
            next: next,
            expires: expires,
        }).unwrap();
    }

    pub fn verify(&self, parent: &IdentityPublicKey) -> Result<ChainLinkContent, ()> {
        parent.verify(&self.content, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.content).map_err(|_| ())?);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ChainLinkContent {
    pub expires: Option<u64>,
    pub next: IdentityPublicKey,
}

pub fn verify_chain(root: &IdentityPublicKey, chain: &[ChainLink], as_of_secs: u64) -> Result<IdentityPublicKey, ()> {
    let mut current = *root;
    for link in chain {
        let content = link.verify(&current)?;
        if let Some(exp) = content.expires {
            if as_of_secs > exp {
                return Err(());
            }
        }
        current = content.next;
    }
    return Ok(current);
}

pub fn verify_chain_now(root: &IdentityPublicKey, chain: &[ChainLink]) -> Result<IdentityPublicKey, ()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| ())?.as_secs();
    return verify_chain(root, chain, now);
}

pub fn verify_signed(
    identity: &Identity,
    root: &IdentityPublicKey,
    chain: &[ChainLink],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if root.identity() != *identity {
        return Err("Root public key doesn't match expected identity".to_string());
    }
    let leaf = verify_chain_now(root, chain).map_err(|_| "Chain verification failed".to_string())?;
    leaf.verify(message, signature).map_err(|e| e.to_string())?;
    return Ok(());
}
