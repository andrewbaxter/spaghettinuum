# TLS

One core feature of Spaghettinuum is that all trust originates from the IDs themselves, which are public keys. This means that once you have an ID, you can use that to establish all other trusted connections (including TLS connections). At this time though, (almost) no software supports TLS via Spaghettinuum so several methods for establishing trust are available.

- Centralized, with a custom `.s`-restricted root CA [certipasta](https://github.com/andrewbaxter/certipasta)

  Any server can get a certificate by signing a request with its identity, for the domain of its identity.

  By installing the root certificate for this CA all software (especially Spaghettinuum non-aware software) can interact with Spaghettinuum servers.

  See that repository for more details.

- Decentralized, via the Spaghettinnuum network

  Hosts generate their own certificate (any way they choose) and publish it via Spaghettinuum (see [the guide to records](./guide_records.md)).

  Clients request both the IP address _and_ the TLS certificate when connecting to a server, then validate that the provided certificate matches the discovered certificate.

- Decentralized, via self signature

  Hosts generate their own certificate with the signature via their identity attached as an extension.

  This is mostly intended for bootstrapping - i.e. connecting to a resolver via TLS or using DNS DoT.

  If a client runs its own resolver this isn't necessary.

These mechanisms are all independent, but most servers will probably use the first two. `spagh-node` and `spagh-auto` will do this automatically when using them as a reverse-proxy or serving static http content.
