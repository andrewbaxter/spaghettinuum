![spaghettinuum](logo.svg)

Spaghettinuum is an alternative to DNS based around a distributed hash table. Replacing the web with a plate of pasta. A little less centralized and a little more noodly.

Featuring:

- DNS bridge
- Smartcard/PCSC/GPG-card identities, optionally, as an excuse to buy a new Yubikey 5 Nano
- A simple RESTy API

Current status: Planned features implemented, but not thoroughly tested

# What is this

- A reference implementation `spagh`, including a fully static as well as a database-backed configuration, plus an HTTP resolver, and a DNS bridge for people still using DNS
- A command line tool `spagh-cli` for interacting with your node, managing identities, publishing data, and generating basic configs
- A Rust library for embedding a resolver/publisher in your own software

Conceptually Spaghettinuum is a distributed two-level key-value store, like DNS

- Level 1: an identity (like a DNS name, but based on your public key)
- Level 2: an arbitrary key (like a DNS record type, but arbitrary)
- Value: a string

You can use it for hosting your websites (or at least, the name bit, almost, several huge caveats below) and providing public service discovery for various services that don't exist yet.

# Installing

Install it with `cargo install spaghettinuum`.

This provides both the server `spagh` and CLI `spagh-cli`.

# Querying

There's a public gnocchi at `spaghetinnuum.isandrew.com`, ip `149.248.205.99`.

## Resolver

It's running a resolver on port `43891`.

You can query arbitrary keys using the CLI (`cargo install spaghettinuum`):

```
spagh-cli query https://spaghetinnuum.isandrew.com:43891 yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r dsf9oyfz83fatqpscp9yt8wkuw
```

or using `curl`:

```
curl https://spaghetinnuum.isandrew.com:43891/yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r?key1,key2,...
```

## DNS bridge

There's a DNS bridge running on UDP port `53`.

Try it out with `dig`:

```
dig @149.248.205.99 yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s
```

If you set your DNS resolver to `149.248.205.99` you can read my writings (WIP) in your browser at <https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s/5987> (WIP - note SSL issues working with traditional infrastructure, discussed below).

## Environment variables

## Resolver API

To query a resolver, send an HTTP `GET` to `RESOLVER/v1/IDENTITY?KEY1,KEY2,...`.

The response has this format:

```json
{
  "v1": {
    "key": {
      "expires": "RFC3339 datetime...",
      "data": "value"
    }
  }
}
```

If the identity can't be resolved you'll get an empty `{"v1": {}}` response.

All resolvers must have this API.

# Hosting a publisher or resolver

1. Do `cargo install spaghettinuum`
2. Run `spagh-cli generate-config` to generate a config
3. Run `spagh --config YOURCONFIG.json` to start the server

The `spagh` server has a number of child services:

- The node (DHT node), required
- A resolver, which provides the REST API for querying, optional
- A publisher, which publishes your key/value pairs, optional
- A DNS bridge, which provides a DNS frontend for querying, optional

# Publishing

## Set up an identity

You need an identity to publish.

There are two types of identities:

- Local (a file on your computer)
- Card (a PCSC/GPG smart card)

To create a local identity, do `spagh-cli new-local-identity me.ident`. It will save the identity and secret in the file, and print out the identity. Anyone who has this file can publish under the identity, so be careful with it.

To use a card identity, with a Yubikey straight out of the extruder,

1. Make sure `pcscd` is running and your Yubikey is plugged in
2. Do `cargo install openpgp-card-tools` which installs `opgpcard`
3. Do `opgpcard list`, which should show your card with an id like `0006:123456789`
4. Install a new private key by doing `opgpcard admin --card 0006:123456789 generate cv25519` with the default `12345678` admin PIN (at the moment, only Ed25519 is supported so to get that you must use `cv25519`). Alternatively you can use Sequoia or something to generate a key then do `opgpcard admin --card XYZ import` instead, if you want to back up your identity. By the way, Sequoia is super cool and the people who work on it are equally amazing.
5. Do `spagh-cli list-card-identities` to confim it's detected and get the identity for the card ID (required for publishing)

The card must be plugged into the server so the server can sign publications.

## Publish your records

To publish you need a server with the publisher service enabled.

Create a json file named `data.json` containing the data you want to publish under your identity:

```json
{
  "missing_ttl": 60,
  "data": {
    "any key you want": {
      "ttl": 60,
      "data": "I love you"
    }
  }
}
```

TTLs are in minutes.

`missing_ttl` is how long keys not in `data` can be assummed to be missing.

Then call

```
spagh-cli publish --server http://localhost local ./identity.json ./data.json
```

to publish using a local identity or

```
spagh-cli publish --server http://localhost card 0006:12345678 - ./data.json
```

to publish using a card.

If you're publishing to a server which requires authorization, you can set environment variable `SPAGH_PUBLISHER_TOKEN` which will be sent as a bearer token with the publishing requests.

## Publishing DNS

DNS is normal published data with DNS-bridge specific keys, with a specific value JSON format understood by the DNS bridge service.

You can use `spagh-cli generate-dns-data` to generate data for use with `spagh-cli publish` or `spagh-cli publish-dns` to publish records directly to a dynamic publisher.

If you want to modify the data, the recognized DNS keys are listed in <src/data/standard.rs>.

## Publishing a website

This is about hacking spaghettinuum into the old technologies, so you can use a plain browser to access your website over the spaghetinnuum.

Note that spaghetinium only handles name resolution - you still need a server to publish the HTTP content, APIs, etc.

The main sticking point here is SSL. There are a couple theoretical options for getting SSL worked out on your website:

1. DNSSEC TLSA records - you could theoretically store a self signed cert in DNS and everything would be great. Unfortunately, anti-progress browsers (Chrome and Firefox) both stonewalled tickets to support TLSA records because who wants the future.
2. A new CA - I'm hoping to set one up, verifying signing requests based on a cert signature using the identity the cert is for. This is a slightly worse approach since everyone would need to add the new CA to their browser (I think you can limit CAs to certain domains, but it's still risky and painful)
3. A SSL MITM proxy - I was thinking about setting a public proxy up, but I was worried about paying for bandwidth
4. Browser extensions(?) that resolve `.s` domains and do the cert validation themselves - I really wanted to avoid this, since browser extensions are getting less capable (ex: manifest v3), require custom extensions for N types of browser, need to deal with hostile publishing review/policies, need to work with Javascript, so on and so forth

TLDR: There's no good options available immediately.

# Architecture

To do a lookup, first

1. You send a request to the resolver
2. The resolver queries the DHT to find the address of the authoritative publisher for the identity. This is like a DNS name server record - it says who is allowed to dictate records for a name.
3. Once the resolver gets the publisher, it opens a TLS connection to the publisher and asks for the keys.
4. It sends you the results

The information in the DHT includes the public key of the TLS cert for the publisher - this is verified when connecting to the publisher.

The DHT is a modified Kademlia which uses public keys for node ids and requires all stored values to be signed with the identity used for the key. This approach is used by other decentralized protocols such as IPFS and Ethereum for their DHTs.

# Why

## Why not DNS

Anarchy

Just kidding. The real reasons for disliking DNS are:

- Paying large amounts of money to rent seeking middlemen
- Pay up or lose everything you've ever built
- Global competition over an artificially limited resource
- Poor DNS registrar security/tech casting your domain names into the void
- Increasing ability for corporations to arrange takeovers
- IANA granting tiny fiefdoms to despots

More and more things rely on DNS: Getting SSL certificates, email, Matrix, that new Twitter replacement. For all the reasons above, the faster we have an alternative the better.

## Gibberish names

Yeah, `google.com` is a lot more memorable than `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s` for sure.

But I live in Japan, and for all intents and purposes people are already living in a world like this:

- Domain names are gibberish - they're heavily biased towards ASCII, which many Japanese find hard to read. In fact, nobody uses domain names directly already - all advertisements say "Search for ABCD" and never include a URL. Browsers search by default so you don't even need to know `google.com`.
- Everyone uses a messenger called Line, which doesn't use any absolute identifiers (no ID or phone number) - instead, you connect with people by adding them via QR code when you meet _in person_, or by adding them via co-membership in a group chat you joined via other people. Companies put QR codes for adding them on Line on posters, advertisements, etc.

While I'm not claiming the googling-companies-thing is great, the Line bit works perfectly and shows how a web of trust model can work in the real world.

In my own internet usage, there are only a couple types of websites I use:

- Stuff I access all the time, which I've bookmarked: Amazon, my bank, Twitter, etc. The bookmark only shows the website title, and I've already vetted them and know they're safe (unless DNS is compromised).
- Stuff I google, which is a _low-trust_ interaction: technical information, blogs, reviews, etc. I confirm all the information is legit independently before relying on it, often from multiple sources. In this case I don't look at the domain anyway.

As more and more domains get used and the number of meaningless suffixes proliferate, the trust provided by a domain name continues to decrease. Is that new bank at `futurebank.io` or `futurebank.cash` or `futurebank.xyz` or `futurebank.it` or (etc). What about typo squatting? What about creative names, like `lyft` vs `lift`?

So safely browsing the web _today_ requires:

1. Establishing trust for new websites via trusted channels: a friend linking you to a website, a company you're doing business with providing a pamphlet with their official website in-person
2. Treating any other websites as untrustworthy: not typing in credit cards, providing your email address, etc

Which would all be the same with gibberish names.

## Text based API

My thoughts were:

- Being able to use curl and/or javascript to create the requests is important for adoption
- Performance isn't critical: DNS isn't in any hot paths, DNS results can be cached and change infrequently so performance isn't as critical
- Encoding binary in UTF-8 isn't hard. Base64 is widely available

A binary API may be available in the future.

## Double hashing

This is a confession.

In order to be compatible with GPG keys (so we can use security card hardware) messages are hashed _twice_ for Ed25519 signing. GPG does the same thing, apparently it's required by the spec.
