//! Spaghettinuum may be used as a library. The library provides both complete
//! server objects as well as methods for creating requests, signing messages, and
//! other peripheral activities.
/// Shared data structures, constants, etc
pub mod interface;

/// DHT node - manages mapping from identities to authoritative publishers
pub mod node;

/// Resolver API service and DNS bridge service
pub mod resolver;

/// Publisher service, dynamic publisher API service
pub mod publisher;

/// Methods for obtaining a `.s` TLS cert
pub mod self_tls;

/// Other assorted methods and tools.
pub mod utils;
