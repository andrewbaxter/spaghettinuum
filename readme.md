![spaghettinuum](readme/logo.svg)

The spaghettinuum is an alternative to the DNS-based web, using a distributed hash table (DHT). Replacing the web with a plate of pasta. A little less centralized and a little more noodly.

---

Create an identity secret:

```
# spagh identity new-local ./my.ident
{ "id": "yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r" }
```

Announce the publisher associated with the identity:

```
# spagh announce local ./my.ident
```

Publish two keys for the identity.

```
# spagh set local ./my.ident - << BODY
{
  "dns/./a": {
    "ttl": 60,
    "data": "v1": ["203.0.113.111"]
  },
  "serial_number": {
    "ttl": 60,
    "data": {
      "long": "1234123412341234-1234",
      "short": "1234"
    }
  }
}
BODY
```

Query the identity `dns/./a` key via DNS.

```
# dig yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s
...
203.0.113.111
...
```

Query the identity `serial_number` key via the resolver API.

```
# spagh get yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r serial_number
{
  "long": "1234123412341234-1234",
  "short": "1234"
}
```

Why it's cool:

- Own your identity - no monthly payments, nobody else can ever use your identity or restrict you from using it
- No hoops to jump through to get an ID, no WHOIS requirements
- DNS bridge for compatibility with existing software
- Get TLS certificates in a single request, no challenge procedure. Or generate your own _secure_ self-signed certificates (validated via DHT)
- Smartcard/PCSC/GPG-card backed identities, optionally, as an excuse to buy a Yubikey 5 Nano

**Current status**: Feature complete but very new -- expect bugs and major changes.

**This repo** is

- An implementation of a node, DNS bridge, CLI, and content hosting tools
- A Rust library for embedding a resolver/publisher in your own software

**Try it out!**

Set up your system to browse the spaghettinuum with [this guide](./readme/guide_browse.md), then try visting my uhh... business card thing at [here](https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s)

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
- [TLS](./readme/tls.md)

# Comparisons with other DNS alternatives

- [Comparisons](./readme/comparison.md)

# Why

## Why not DNS

DNS often functions as an identity: who you are online is often tied to a domain name, like your email address. Every day more things rely on DNS... encryption (TLS cert issuing validations), Matrix, that new Twitter replacement.

Having an such an identity is important, but despite regulations the DNS system locks you in to all sorts of abuse:

- Paying increasingly large amounts of money to rent seeking middlemen

- Keep paying or lose everything

- Compete (financially) over an artificially limited resource

- Poor DNS registrar security/tech casting your domain names into the void

- Large corporations can take over bit player domains

- IANA granting tiny fiefdoms to despots

The sooner we have a good decentralized alternative the better.

## Gibberish names are OK

Yeah, `google.com` is a lot more memorable than `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`.

But I live in Japan, and for all intents and purposes people here are already living in a world where domain names are just gibberish:

- Domain names are heavily biased towards ASCII, which many Japanese find hard to read. In fact, nobody here uses domain names directly - all advertisements say "Search for ABCD" and never include a URL. Browsers come with search engines preconfigured so you don't even need to know how to type in `google.com` (is there a `www`? do you need to add `https://`?).
- Everyone uses a messenger called Line, which doesn't use any visible absolute identifiers (ID or phone number) - instead, you connect with people by adding them via QR code when you meet _in person_, or by adding them via co-membership in a group chat you joined via other people. Companies put QR codes for adding them on Line on posters, advertisements, etc. Mutual acquaintences create groups so people they know can add eachother.

While I'm not claiming the googling-companies-thing is great, the Line bit works well and shows how a world with no absolute names is still perfectly navigable.

I don't rely on domain names to establish trust in my own internet usage too:

- Stuff that I rely on (_high-trust_) and access all the time: Amazon, my bank, Twitter, etc.

  I was introduced to them by trusted connections like friends, family, pamphlets from branches of physical stores. These may have been sent as hyperlinks or QR codes where unless I dug in I didn't see the actual domain name.

  Once I accessed them I bookmarked them, and again the bookmark only shows the website title (or a bookmark title I gave it myself).

- Stuff I find in search results, which I use for _low-trust_ interactions only: technical information, blogs, reviews, etc.

  I confirm all the information is legitimate independently before relying on it, often from multiple sources. In this case I (again) don't look at the domain.

As more and more domains are purchased and the number of meaningless suffixes proliferate, the trust provided by a domain name continues to decrease. Is that new bank at `futurebank.io` or `futurebank.cash` or `futurebank.xyz` or `futurebank.it` or (etc). What about typo squatting? What about creative names, like `lyft` vs `lift`? What about all the entirely unrelated sibling domains corporations buy and use for core site operations with no thoughts to validation?

So safely browsing the web _today_ requires:

1. Establishing trust for new websites via other trusted channels
2. Establishing personally relevant non-absolute identifiers (ex: bookmark titles, hyperlink text) because nobody remembers domain names anyways
3. Treating any other websites as untrustworthy

Which would all be the same with gibberish names.

## Censorship and anonymity

Unlike something like IPFS where everything is naturally decentralized (including the content), with Spaghettinuum only the publisher announcements (SOA records) use peer-to-peer hosting and distribution.

This means that unless you ensure resiliance yourself (ex: by setting up multiple servers, announcers) a Spaghettinuum site can be taken down either by taking down the publisher or the hosting server.

Generally speaking, peer-to-peer hosting and other similar techniques have restrictions such as requiring static content, data size restrictions, client computation memory and cpu burdens, and general complexity.

I feel like the most important piece to decentralize is the name: even if everything else is taken down and even if there is some downtime, as long as you still control your name you can re-host your site somewhere else later. In order to make hosting dynamic content (services, private databases) Spaghettinuum focuses on just decentralizing the name. I hope that the simplicity also makes it easier to adopt and more stable.

I hope to support improved censorship resistance and anonymity though as far as it doesn't impact other goals.

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

# Availability

The publisher announcements are decentralized with redundancy and are therefore highly available and censorship resistant.

One or more publishers can be announced, any of which can be used for resolution in case others fail. This allows publisher redundancy provides for simple load balancing.

Additional redundancy can be done by replicating keys and republishing data if publishers become unavailable.
