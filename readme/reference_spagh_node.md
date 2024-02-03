# Command: `spagh-node`

This is the core of the Spaghettinuum. It runs a DHT node, and then optionally:

- Run a resolver

- Run a DNS bridge resolver

- Run a publisher

There's a public resolver/DNS bridge so you don't necessarily need that.

However, if you want to publish anything (website, service discovery, etc) you'll need a publisher or you'll need to get your identity authorized on someone else's publisher.

## Installation

Install with `cargo install spaghettinuum`.

## Environment variables

- `SPAGH_CONFIG` - The config JSON itself, if not using the `--config` command line parameter. This is useful for running in Docker containers and the like.

## Usage

1. Write the configuration. Notes:

   To you need to provide a bootstrap node. The configuration for the official Antipasta bootstrap node configuration is [here](https://github.com/andrewbaxter/antipasta#bootstrap-a-spaghettinuum-node), but there may be more community nodes later. More bootstrap nodes will increase reliability.

   There are several ports that may be open:

   - DHT port, UDP - this is public, for node-node traffic

   - Resolve port, HTTPS - this is public, for node-node traffic

   - API port, HTTP/HTTPS - this is the endpoint for the API (publishing, resolving, administration) including CLI commands. This may be public or private, it does not affect participation in the network. If you set up auto-cert it will be HTTPS, otherwise HTTP.

   - DNS ports, UDP, TCP - these are ports used for DNS resolvers. They may be public or private (if it's a private resolver)

   See the [example config](./examples/spagh_node_full.json). Note that there are mutually exclusive choices for ex: identifying global addresses. The config shows one way (interface detection), but refer to the jsonschema for other configuration methods (external ip checking service, static configuration).

   The config must match [this jsonschema](./schemas/config_spagh_node.schema.json).

1. Start the server with

   - `./spagh-node --config config.json`
   - `cat config.json | ./spagh-node --config -`
   - or `SPAGH_CONFIG=... ./spagh-node`

## Authorizing publishing

If you're running a publisher, you can allow and disallow identities to publish using [`spagh`](./reference_spagh.md).

Make sure `SPAGH` points to the publisher, and these are admin commands so you must set `SPAGH_ADMIN_TOKEN`.

- Allow an identity to publish

  `spagh admin allow-identity yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`

- Disallow an identity from publishing

  `spagh admin disallow-identity yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`

- List identities currently allowed to publish

  `spagh admin list-allowed-identities`
