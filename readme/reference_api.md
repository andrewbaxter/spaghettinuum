# Reference: API

## HTTP

### Lookup

Lookup is

Do `GET` `https://URL/v1/ID?KEY1,KEY2,KEY3` where

- `URL` is the URL of a resolver.

- `ID` is the identity ID, like `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`

- `KEY1` `KEY2` `KEY3` are any url-encoded strings. Decoded, these should match the keys in the published `data` exactly.

This will return a JSON value in the format:

```json
{
    "KEY1": {
        "expires": "...",
        "data": ...
    },
    "KEY2": {
        "expires": "...",
        "data": null
    },
    ...
}
```

Data is the same JSON `data` in the published record. If a value for a key is not found, the key will be present in the output but the corresponding data will be `null`.

See [this schema](TODO) for more details.

## Rust

### DHT node

This allows you to operate a DHT node, with methods for looking up and announcing publisher locations. This is used by the Publisher and Resolver services below.

See [`Node::new`](TODO)

### Publisher

Publisher manages a database of records and handles announcement via the DHT node. It has methods for publishing and unpublishing data. It can be integrated with other applications to programmatically publish values.

See [`Publisher::new`](TODO)

### Resolver

The resolver has a single method, `get`, which encapsulates publisher lookup via DHT and communication with the publisher to retrieve values.

See [`Resolver::new`](TODO)
