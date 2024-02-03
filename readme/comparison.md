# Comparisons

These are intended to be comparisons over general design rather than specific features. If I have details wrong or there's an alternative please let me know.

## Namecoin, ENS, Handshake, etc.

Namecoin and similar share the issue of competition over a scarce resource with DNS. The main differentiator vs DNS is that a blockchain is the arbitor, not an organization.

## Gnu Name System

Gnu Name System (GNS) is very similar to Spaghettinuum: globally unique names, DHT storage. These similarities extend to how many issues are solved.

I think the fundamental differences are:

- Spaghettinuum is small and focused. GNS is part of GNUNet and has many modes of operation, commands and command line flags, subsystems and components.

- Spaghettinuum has a light-client + server model, where local usage can be done with just a standard DNS or HTTP client (ex: curl). GNS is a heavy-client model, where you're expected to have a full installation on each device you use it on, which will then be a member of the network.

- Spaghettinuum is an HTTP JSON key-value store, with support for bridging to DNS. GNS is primarily a DNS replacement, storing DNS(-like) records internally.

Some more subtle differences:

- GNS operates under the assumption that users will establish human readable DNS names mapping public keys, rather than use the public key ids directly. It comes with predefined mappings including one that acts as a centralized registry for other users, with the same name scarcity issues. You can also use the public key ids directly, so there are multiple ways to access a site.

  Spaghettinuum has only one access method - using the public key (identity) id. There are no central registries. I don't believe establishing human readable labels at the DNS level is a good interface - see "Gibberish names are OK" for more info.

- GNS stores all records in the DHT. Spaghettinuum only stores pointers to the authoritative publisher in the DHT, everything else is stored on the publisher.

- GNS uses a local MITM HTTPS proxy (with local CA cert) to handle TLS certificates, Spaghettinuum uses a new root CA cert and public issuer (Certipasta). For both, these are expected to be temporary measures until browsers support other channles for distributing TLS certificates.

## IPNS

IPNS development was specific to IPFS use cases last I checked: [no arbitrary data, publishing tied tightly to nodes](https://github.com/ipfs/notes/issues/439).

There have been complaints that IPFS is slow, possibly relating to using TCP for the DHT.
