# Command: `spagh`

This is _the_ software. It has tools for working with servers, and you also use it to run a server via `spagh demon`.

The below provides an overview, but for detailed documentation see `spagh -h`.

## Installation

Install with `cargo install spaghettinuum` or use the [Docker image](https://github.com/andrewbaxter/spaghettinuum/pkgs/container/spaghettinuum).

## As a client

You can use it to:

- Look up records, make HTTP requests, use SSH

  HTTP and SSH requests use out of band (distributed via spaghettinuum records) server certificate validation.

- Publish records

- Check node health

- Administer the node (ex: allow an identity to publish)

By default this looks up the system configured DNS resolver and connects to it on the default API port, assuming it's a Spaghettinuum node. To use a different node or port, see the `SPAGH` environment variable.

### Environment variables

- `SPAGH` - List of API URLs of nodes to access. For querying this would be resolver URLs, for publishing this would be publisher URLs (depending on your hosting they may be different nodes).

  When publishing, all listed publisher URLs will be announced. This can be used for simple load balancing and redundancy. You should probably limit this to a reasonable number (like 3) to avoid announcement packets going over the UDP MTU.

  Examples: `SPAGH=https://203.0.113.111,https://203.0.113.112` or `SPAGH=https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`

- `SPAGH_TOKEN` - The token configured on a node to authorize administrative actions. This is the same value as specified in the config.

  Examples: `SPAGH_TOKEN=abcd1234`

## As a server

To run a server, just do `spagh demon my_config.json`.

The server is fundamentally a collection of related but distinct functions enabled individually in the config.

### Configuration

The config has two sets of configuration:

Inputs:

- How to determine advertisable IPs

- An identity to use, if publishing

Functions:

- The `node` - the DHT participant (this is always on)

- Publisher functionality, for publishing records with the configured identity

- Resolver functionality, for looking up records

- The DNS resolver bridge

- Automatically publishing host records such as IP, SSH host keys, and TLS certs

- Serving traffic (static or reverse-proxied) with a cert for the configured identity

You can find the configuration JSON Schema [here](./schemas/config_spagh_node.schema.json).

An example is available [here](./examples/spagh_node_full.json). This shows all required configuration to enable all functionality, and several variations of some options.

The schema can be used as a root level `"$schema"` key in the config so VS Code will autocomplete config options and provide documentation hints.

Alternatively, you can run `spagh demon my_config.json --validate` which will check the config and exit.

### Ports

The server uses up to three sockets:

- UDP for the node DHT participation - this must be public

- TCP for the publisher - this must also be public, so that resolvers can contact it to look up records

- TCP for the API - this can be public or private depending on what systems you want to have interact with the node

All TCP endpoints use HTTPS (always) so no wrapping is necessary.

### Publishing authorization

If you're running a publisher, you can allow and disallow identities to publish using the [`spagh`] client commands.

Make sure `SPAGH` points to the publisher, and these are admin commands so you must set `SPAGH_ADMIN_TOKEN`.

- Allow an identity to publish

  `spagh admin allow-identity yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`

- Disallow an identity from publishing

  `spagh admin disallow-identity yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`

- List identities currently allowed to publish

  `spagh admin list-allowed-identities`

### Environment variables

- `SPAGH_CONFIG` - The config JSON itself, if not using the `--config` command line parameter. This is useful for running in Docker containers and the like.

