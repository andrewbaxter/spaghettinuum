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

## Typical request flow

In a normal environment, a client that wishes to make an HTTP connection to a server would make these requests:

1. Request `CNAME`, `AAAA`, `A`, and out of band TLS keys from the spghettinuum resolver.

   It assumes that the locally configured DNS resolvers (ex: in `resolv.conf`) are spaghettinuum resolvers. The requests are made using the spaghettinuum HTTPS request API rather than DNS.

   Resolver TLS certificates aren't validated because there's no available associated DNS name (and consequently, identity) for the resolver. Support may be added for manually providing a name/identity.

2. The resolver queries the DHT for an announcement for the request identity
3. The resolver requests the keys from the identity's publisher identified in the announcement.

   The announcement contains the publisher ips and TLS certificate, which the resolver uses to connect.

4. The resolver responds to the client with the requested values if they were present

5. As long as `CNAME` records are returned, the client repeats from 1. with the new name
6. The client connects to the server via the `AAAA` or `A` values.

   The server certificate is validated via the returned TLS keys, an identity-based signature of the SPKI, or using typical centralized certificate validation methods (locally installed CA certs).
