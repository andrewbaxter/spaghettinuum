use {
    crate::versioned,
    der::oid::ObjectIdentifier,
};

pub mod v1;

pub use v1 as latest;

pub fn x509_ext_pagh_oid() -> ObjectIdentifier {
    return ObjectIdentifier::new("TODO").unwrap();
}

versioned!(
    X509ExtSpagh,
    Clone;
    (V1, 1, v1::X509ExtSpagh)
);
