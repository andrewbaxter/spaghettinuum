use {
    crate::interface::{
        stored::{
            node_identity::{
                NodePublicKey,
                NodePublicKeyMethods,
                NodeSecret,
                NodeSecretMethods,
            },
            self,
        },
        wire,
    },
    serde::{
        Serialize,
        de::DeserializeOwned,
    },
    spaghettinuum::{
        byteszb32::BytesZb32,
        interface::{
            identity::IdentityPublicKey,
            signature_chain::ChainLink,
        },
        jsonsig::JsonSignature,
    },
    super::identity_secret::IdentitySigner,
};

pub trait IdentSignatureMethods<B: DeserializeOwned, I>
where
    Self: Sized {
    fn parse_unwrap(&self) -> B;
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(I, Vec<ChainLink>, Self), loga::Error>;
    fn verify(&self, leaf: &IdentityPublicKey) -> Result<B, ()>;
}

impl<
    B: Serialize + DeserializeOwned,
> IdentSignatureMethods<B, IdentityPublicKey> for JsonSignature<B, IdentityPublicKey> {
    fn parse_unwrap(&self) -> B {
        return serde_json::from_str(&self.message).map_err(|_| ()).unwrap();
    }

    fn sign(
        signer: &mut dyn IdentitySigner,
        body: B,
    ) -> Result<(IdentityPublicKey, Vec<ChainLink>, Self), loga::Error> {
        let message = serde_json::to_string(&body).unwrap();
        let (root_public_key, chain, signature) = signer.sign(message.as_bytes())?;
        return Ok((root_public_key, chain, Self {
            message: message,
            signature: BytesZb32(signature),
            _p: Default::default(),
        }));
    }

    fn verify(&self, leaf: &IdentityPublicKey) -> Result<B, ()> {
        leaf.verify(self.message.as_bytes(), &self.signature.0).map_err(|_| ())?;
        return Ok(serde_json::from_str(&self.message).map_err(|_| ())?);
    }
}

impl<
    B: Serialize + DeserializeOwned,
> IdentSignatureMethods<B, IdentityPublicKey> for stored::announcement::v1::BincodeSignature<B, IdentityPublicKey> {
    fn parse_unwrap(&self) -> B {
        return bincode::deserialize(&self.message).map_err(|_| ()).unwrap();
    }

    fn sign(
        signer: &mut dyn IdentitySigner,
        body: B,
    ) -> Result<(IdentityPublicKey, Vec<ChainLink>, Self), loga::Error> {
        let message = bincode::serialize(&body).unwrap();
        let (root_public_key, chain, signature) = signer.sign(&message)?;
        return Ok((root_public_key, chain, Self {
            message: message,
            signature: signature,
            _p: Default::default(),
        }));
    }

    fn verify(&self, leaf: &IdentityPublicKey) -> Result<B, ()> {
        leaf.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }
}

impl<
    B: Serialize + DeserializeOwned,
> IdentSignatureMethods<B, IdentityPublicKey> for wire::node::v1::BincodeSignature<B, IdentityPublicKey> {
    fn parse_unwrap(&self) -> B {
        return bincode::deserialize(&self.message).map_err(|_| ()).unwrap();
    }

    fn sign(
        signer: &mut dyn IdentitySigner,
        body: B,
    ) -> Result<(IdentityPublicKey, Vec<ChainLink>, Self), loga::Error> {
        let message = bincode::serialize(&body).unwrap();
        let (root_public_key, chain, signature) = signer.sign(&message)?;
        return Ok((root_public_key, chain, Self {
            message: message,
            signature: signature,
            _p: Default::default(),
        }));
    }

    fn verify(&self, leaf: &IdentityPublicKey) -> Result<B, ()> {
        leaf.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }
}

pub trait NodeIdentSignatureMethods<B: DeserializeOwned> {
    fn sign(identity: &NodeSecret, body: B) -> Self;
    fn verify(&self, identity: &NodePublicKey) -> Result<B, ()>;
}

impl<
    B: Serialize + DeserializeOwned,
> NodeIdentSignatureMethods<B> for wire::node::v1::BincodeSignature<B, NodePublicKey> {
    fn sign(identity: &NodeSecret, body: B) -> Self {
        let message = bincode::serialize(&body).unwrap();
        return Self {
            signature: identity.sign(&message),
            message: message,
            _p: Default::default(),
        };
    }

    fn verify(&self, identity: &NodePublicKey) -> Result<B, ()> {
        identity.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }
}
