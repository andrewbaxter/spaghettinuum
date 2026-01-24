use {
    super::identity_secret::IdentitySigner,
    crate::interface::{
        stored::{
            self,
            node_identity::{
                NodeIdentity,
                NodeIdentityMethods,
                NodeSecret,
                NodeSecretMethods,
            },
        },
        wire,
    },
    serde::{
        Serialize,
        de::DeserializeOwned,
    },
    spaghettinuum::{
        byteszb32::BytesZb32,
        interface::identity::Identity,
        jsonsig::JsonSignature,
    },
};

pub trait IdentSignatureMethods<B: DeserializeOwned, I>
where
    Self: Sized {
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(I, Self), loga::Error>;
    fn verify(&self, identity: &Identity) -> Result<B, ()>;
    fn parse_unwrap(&self) -> B;
}

impl<
    B: Serialize + DeserializeOwned,
> IdentSignatureMethods<B, Identity> for stored::announcement::v1::BincodeSignature<B, Identity> {
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(Identity, Self), loga::Error> {
        let message = bincode::serialize(&body).unwrap();
        let (ident, signature) = signer.sign(&message)?;
        return Ok((ident, Self {
            message: message,
            signature: signature,
            _p: Default::default(),
        }));
    }

    fn verify(&self, identity: &Identity) -> Result<B, ()> {
        identity.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }

    fn parse_unwrap(&self) -> B {
        return bincode::deserialize(&self.message).map_err(|_| ()).unwrap();
    }
}

impl<
    B: Serialize + DeserializeOwned,
> IdentSignatureMethods<B, Identity> for wire::node::v1::BincodeSignature<B, Identity> {
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(Identity, Self), loga::Error> {
        let message = bincode::serialize(&body).unwrap();
        let (ident, signature) = signer.sign(&message)?;
        return Ok((ident, Self {
            message: message,
            signature: signature,
            _p: Default::default(),
        }));
    }

    fn verify(&self, identity: &Identity) -> Result<B, ()> {
        identity.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }

    fn parse_unwrap(&self) -> B {
        return bincode::deserialize(&self.message).map_err(|_| ()).unwrap();
    }
}

impl<B: Serialize + DeserializeOwned> IdentSignatureMethods<B, Identity> for JsonSignature<B, Identity> {
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(Identity, Self), loga::Error> {
        let message = serde_json::to_string(&body).unwrap();
        let (ident, signature) = signer.sign(message.as_bytes())?;
        return Ok((ident, Self {
            message: message,
            signature: BytesZb32(signature),
            _p: Default::default(),
        }));
    }

    fn verify(&self, identity: &Identity) -> Result<B, ()> {
        identity.verify(self.message.as_bytes(), &self.signature.0).map_err(|_| ())?;
        return Ok(serde_json::from_str(&self.message).map_err(|_| ())?);
    }

    fn parse_unwrap(&self) -> B {
        return serde_json::from_str(&self.message).map_err(|_| ()).unwrap();
    }
}

pub trait NodeIdentSignatureMethods<B: DeserializeOwned> {
    fn sign(identity: &NodeSecret, body: B) -> Self;
    fn verify(&self, identity: &NodeIdentity) -> Result<B, ()>;
}

impl<
    B: Serialize + DeserializeOwned,
> NodeIdentSignatureMethods<B> for wire::node::v1::BincodeSignature<B, NodeIdentity> {
    fn verify(&self, identity: &NodeIdentity) -> Result<B, ()> {
        identity.verify(&self.message, &self.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.message).map_err(|_| ())?);
    }

    fn sign(identity: &NodeSecret, body: B) -> Self {
        let message = bincode::serialize(&body).unwrap();
        return Self {
            signature: identity.sign(&message),
            message: message,
            _p: Default::default(),
        };
    }
}
