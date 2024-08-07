# Command: `spagh`

This is a command line tool for working with the various servers. You can use it to:

- Look up records, make HTTP requests, use SSH

  HTTP and SSH requests use out of band (distributed via spaghettinuum records) server certificate validation.

- Publish records

- Check node health

- Administer the node (ex: allow an identity to publish)

By default this looks up the system configured DNS resolver and connects to it on the default API port, assuming it's a Spaghettinuum node. To use a different node or port, see the `SPAGH` environment variable.

## Installation

Install with `cargo install spaghettinuum` or use the [Docker image](https://github.com/andrewbaxter/spaghettinuum/pkgs/container/spaghettinuum).

## Environment variables

- `SPAGH` - List of API URLs of nodes to access. For querying this would be resolver URLs, for publishing this would be publisher URLs (depending on your hosting they may be different nodes).

  When publishing, all listed publisher URLs will be announced. This can be used for simple load balancing and redundancy. You should probably limit this to a reasonable number (like 3) to avoid announcement packets going over the UDP MTU.

  Examples: `SPAGH=https://203.0.113.111,https://203.0.113.112` or `SPAGH=https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`

- `SPAGH_TOKEN` - The token configured on a node to authorize administrative actions. This is the same value as specified in the config.

  Examples: `SPAGH_TOKEN=abcd1234`

## Usage

See `spagh -h`
