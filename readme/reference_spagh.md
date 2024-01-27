# Command: `spagh`

This is a command line tool for working with the various servers. You can use it to:

- Look up records

- Publish records

- Check node health

- Administer the node (ex: allow an identity to publish)

## Installation

Install with `cargo install spaghettinuum`.

## Environment variables

- `SPAGH` - API URL of node to access. For querying this would be the address of a resolver node, but for publishing this would be the url of a publisher node (depending on your hosting they may be different nodes).

  Examples: `SPAGH=https://256.256.256.256` or `SPAGH=https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`

- `SPAGH_TOKEN` - The token configured on a node to authorize administrative actions. This is the same value as specified in the config.

  Examples: `SPAGH_TOKEN=abcd1234`

## Usage

See `spagh -h`
