# Reference: Architecture (and design decisions)

At a high level, there are three server components:

- (DHT) Node
- Publisher
- Resolver

When a client publishes data it sends 1. record data for an identity and 2. announcement data for the same identity to the publisher, which

1. Stores the record in its database
2. Puts the announcement in the DHT via its DHT node

A client wants to look up a record sends the request to a resolver, which

1. Queries the DHT for the announcement to learn the publisher (and the publisher's IP)
2. Contacts the publisher in the announcement and asks for the record

The announcement is like an SOA DHT record - it says which publisher is authoritative for the record data (and how to reach the publisher), and is signed by the identity.

## DHT architecture

The DHT is roughly based on Kademlia with some common modifications:

- Node identities are public keys
- Messages are signed
- Liveness checks involve completing a challenge to prove the identity

When multiple values are found for a query, the one with the latest data (as signed by the publishing identity) is preferred.

It uses UDP since much of the protocol is designed around an unreliable network.

## Publisher and announcements

Announcements contain the publisher's TLS cert and IP address. Note that the publisher TLS cert is not the same cert used by the API which may be consumed by normal HTTP clients. When the resolver contacts the publisher, only the TLS certificate identified in the announcement is accepted.

The publisher exposes an HTTPS endpoint for the resolver. This endpoint is a simple key-value lookup, with the key being the identity and an extra key string, and the value being the published data (arbitrary JSON).

## DNS bridge

DNS records are converted to JSON structures and stored with keys corresponding to the record type. The bridge performs lookup as it would for any other spahgettinuum data, and converts the JSON back to a DNS response.
