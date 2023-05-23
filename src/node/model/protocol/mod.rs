pub mod v1;

pub use v1::*;
use crate::versioned;

versioned!(
    Protocol,
    Debug;
    (V1, 1, v1::Message)
);
