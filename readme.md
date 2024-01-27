![spaghettinuum](logo.svg)

The spaghettinuum is an alternative to DNS based around a distributed hash table (DHT). Replacing the web with a plate of pasta. A little less centralized and a little more noodly.

Why it's cool:

- Own your identity - even if you quit, nobody else can use your identity
- No hoops to jump through to get an ID, no WHOIS information
- Simple, both design and use
- DNS bridge for compatibility with existing software
- Smartcard/PCSC/GPG-card backed identities, optionally, as an excuse to buy a Yubikey 5 Nano

**Current status**: Feature complete but very new -- expect bugs.

_This repo_ is

- An implementation of a node, DNS bridge, CLI, and content hosting tools
- A Rust library for embedding a resolver/publisher in your own software

_Try it out!_

Set up your system to browse the spaghettinuum with [this guide](./readme/guide_browse.md), then try visting my blog at [here](TODO)

Try using it to host a site, send email, or do service discovery.

# Guides

- [Browse the spaghettinuum](./readme/guide_browse.md)
- [Publishing](./readme/guide_publishing.md)
- [Identities](./readme/guide_identities.md)

# Reference

- [`spagh-node`](./readme/reference_spagh_node.md) - the network node server, resolver, and publisher
- [`spagh`](./readme/reference_spagh.md) - the CLI
- [`spagh-auto`](./readme/reference_spagh_auto.md) - a small static file server/reverse proxy
- [API reference](./readme/reference_api.md)
- [Architecture](./readme/architecture.md)

# Comparisons with other DNS alternatives

- [Comparisons](./readme/comparison.md)

# Why

## Why not DNS

DNS often functions as an identity - who you are online is often tied to a domain name, like your email address. Every day more things rely on DNS: encryption (TLS cert issuing validations), Matrix, that new Twitter replacement.

Having an such an identity is important, but despite regulations the DNS system locks you in to all sorts of abuse:

- Paying large amounts of money to rent seeking middlemen

- Keep paying or lose everything

- Compete (financially) over an artificially limited resource

- Poor DNS registrar security/tech casting your domain names into the void

- Large corporations can take over bit player domains

- IANA granting tiny fiefdoms to despots

The sooner we have a good decentralized alternative the better.

## Gibberish names are OK

Yeah, `google.com` is a lot more memorable than `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`.

But I live in Japan, and for all intents and purposes people are already living in a world where domain names are just gibberish:

- Domain names are heavily biased towards ASCII, which many Japanese find hard to read. In fact, nobody here uses domain names directly - all advertisements say "Search for ABCD" and never include a URL. Browsers come with search engines preconfigured so you don't even need to know how to type in `google.com` (is there a `www`? do you need to add `https://`?).
- Everyone uses a messenger called Line, which doesn't use any visible absolute identifiers (ID or phone number) - instead, you connect with people by adding them via QR code when you meet _in person_, or by adding them via co-membership in a group chat you joined via other people. Companies put QR codes for adding them on Line on posters, advertisements, etc.

While I'm not claiming the googling-companies-thing is great, the Line bit works well and shows how a world with no absolute names is still perfectly navigable.

In my own internet usage too I don't rely on domain names to establish trust:

- Stuff that I rely on (_high-trust_) and access all the time: Amazon, my bank, Twitter, etc.

  I was introduced to them by trusted connections like friends, family, pamphlets from branches of physical stores. These may have been sent as hyperlinks or QR codes where unless I dug in I didn't see the actual domain name.

  Once I accessed them I bookmarked them, and again the bookmark only shows the website title (or a bookmark title I gave it myself).

- Stuff I find in search results, which is a _low-trust_ interaction: technical information, blogs, reviews, etc.

  I confirm all the information is legitimate independently before relying on it, often from multiple sources. In this case I (again) don't look at the domain.

As more and more domains are purchased and the number of meaningless suffixes proliferate, the trust provided by a domain name continues to decrease. Is that new bank at `futurebank.io` or `futurebank.cash` or `futurebank.xyz` or `futurebank.it` or (etc). What about typo squatting? What about creative names, like `lyft` vs `lift`?

So safely browsing the web _today_ requires:

1. Establishing trust for new websites via other trusted channels
2. Establishing personally relevant non-absolute identifiers (ex: bookmark titles, hyperlink text) because nobody remembers domain names anyways
3. Treating any other websites as untrustworthy

Which would all be the same with gibberish names.

# Privacy

Communication between the client and the resolver (lookup) is secured by HTTPS, or optionally DoT for the DNS bridge.

Communication between the nodes in the DHT (announcement) is public.

Communication between the resolver and publisher (lookup) is secured by HTTPS.

The resolver knows what records the clients request.

The publisher knows which resolvers request which records. If K users share a resolver they have K-anonymity to the publisher.

An external observer can see which clients communicate with which resolvers, and which resolvers communicate with which publishers. If K users share a resolver, and L users share a publisher, they have KL-anonymity to the external observer regarding which records they may look up.

Once the lookup is complete, clients communicate directly with hosts, the same way they do currently with HTTP after DNS lookups.

# Security

1. All publisher announcements (DHT data saying which publisher is authoritative for an identity's data) are signed by an identity. The announcements are dated and conforming nodes will ignore older announcements when a newer announcement is available.

2. All records on the publisher are also signed by the publishing identity.

The resolver validates the signatures against the identity id (the identity's public key) when it receives them before returning the data.
