# Command: `spagh-auto`

This is a small helper for hosting content on the spaghettinuum. It can do the following:

- Publish its own IP (A/AAAA)

- Obtain TLS certs for its `.s` address, storing them in a directory

- Serve static content over TLS

- TLS reverse proxy another server

## Installation

Install with `cargo install spaghettinuum`.

## Environment variables

- `SPAGH` - API URL of publisher node

- `SPAGH_CONFIG` - The config file JSON itself, if not using the `--config` command line parameter. This is useful for running in Docker containers and the like.

## Usage

1. Get an identity for the server to publish itself as

   See [Identities](./guide_identities.md) for more details

1. Authorization to publish via a publisher

   You can either host your own publisher node or get access from a publishing provider. You'll need the API URL for the publisher for the config.

1. Write the configuration

   This is a minimal [example config](TODO) that just publishes the server's public IP as DNS-equivalent records, but see the [publishing guide](./guide_publishing.md) for serving static files or a reverse proxy.

   Refer to [the jsonschema](TODO)

1. Start the server with

   - `./spagh-auto --config config.json`
   - `cat config.json | ./spagh-auto --config -`
   - or `SPAGH_CONFIG=... ./spagh-auto`
