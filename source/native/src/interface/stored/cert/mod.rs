pub mod v1;

pub use v1 as latest;
use {
    der::oid::ObjectIdentifier,
    spaghettinuum::versioned,
};

versioned!(
    X509ExtSpagh,
    Clone;
    (V1, 1, v1::X509ExtSpagh)
);

pub const X509_EXT_SPAGH_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62178");
