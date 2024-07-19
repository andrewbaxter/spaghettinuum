use {
    crate::versioned,
    der::oid::ObjectIdentifier,
};

pub mod v1;

pub use v1 as latest;

pub fn x509_ext_pagh_oid() -> ObjectIdentifier {
    // Andrew Baxter, LLC. expressly for the spaghettinuum x509 extension section
    return ObjectIdentifier::new("1.3.6.1.4.1.62178").unwrap();
}

versioned!(
    X509ExtSpagh,
    Clone;
    (V1, 1, v1::X509ExtSpagh)
);