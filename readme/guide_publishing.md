# Guide: Publishing

Publishing means associating data with your id and publicizing it so that anyone else who knows your id can access it. This data can be anything - IP addresses, keys, names, contact info, status updates, etc.

In order to publish, you'll need:

- An [identity](./guide_identities.md)
- A publisher - either [set your own up](./reference_spagh_node.md) or get your identity authorized on a publisher run by someone else

## Manual publishing

To manually publish, you'll need the [`spagh`](./reference_spagh.md) - follow that link for setup instructions.

Suppose you have a JSON file `data.json`

```json
{
  "serial_number": {
    "ttl": 60,
    "data": {
      "long": "1234123412341234-1234",
      "short": "1234"
    }
  }
}
```

- `data` is an arbitrary JSON value associated with the key that will be returned from queries.

- `ttl` (minutes) is how long a successfully resolved value can be cached by a resolver.

and you want to publish it under your identity `my.ident` with ID `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`.

Set the environment variable `SPAGH` to the URL of your publisher and run

```
$ spagh publish announce local my.ident
$ spagh publish set local my.ident ./data.json
```

(in any order). The first advertises the publisher you're connecting to as authoritative for the identity, the second puts the data in the database.

Anyone can now look it up by doing

```
$ spagh get yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r serial_number
{
    "long": "1234123412341234-1234",
    "short": "1234"
}
```

### Publishing DNS bridge records

The DNS bridge allows accessing keys and values with a specific format via DNS, so you can (for example) type an identity into your browser address bar and access an IP published for that identity in Spaghettinuum.

Spaghettinuum key/value pairs that match the format expected by the DNS bridge will be referred to as DNS equivalent records.

The easy way to publish DNS equivalent records is using the command line like:

```
$ spagh publish set-dns local my.ident --subdomain c.b.a --a 203.0.113.111 --aaaa 2001:db8::8a2e:370:7334
```

This would resolve `A` and `AAAA` queries for the DNS name `c.b.a.IDENT.s` (note the subdomain order).

You can also do it using the normal `set` command. In that case, the keys must be like `a.b.c.dns/a` (note the path here is top-level-down, and the final segment is `dns/a` corresponding to the record type).

DNS record types each have different JSON structures that must be mapped to and from JSON, with only a subset supported at the moment. See [the guide to records](./guide_records.md) for more information.

## Setting up a static file server

The `spagh-auto` is the simplest way to set up a static file server, and will handle both publishing `.s` DNS bridge records and obtaining a `.s` TLS certificate.

Set up `spagh-auto` per [the reference](./reference_spagh_auto.md).

You can use this [example config](./examples/spagh_auto_static_files.json).

Once you've started it, you can visit the site at `https://IDENT.s` (with some assumptions: 1. you've set up DNS and the Certipasta root certificate, see [the guide to browsing](./guide_browse.md) 2. you're using IPv6 so there's no split horizon or else the server isn't in your local LAN, otherwise routing won't work).

## Setting up a reverse proxy

If you want to serve more complex software, the simplest way is to run that software over HTTP bound to `127.0.0.1` and then set up a spaghettinuum reverse proxy to expose it.

The `spagh-auto` command will do both of these for you.

Set up `spagh-auto` per [the reference](./reference_spagh_auto.md).

You can use this [example config](./examples/spagh_auto_reverse_proxy.json).

## Using external software

If you omit `content` from the examples above, `spagh-auto` will manage the certs in the directory but serve no content itself. You can then use external software like nginx to serve content.
