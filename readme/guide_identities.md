# Guide: Identities

Spaghettinuum distinguishes "identity" from "id" (as in "identifier"). The former is complex data (a private key), where the latter is a simple string (like `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`) which identifies the former, like a name.

There are two types of identities:

- Node identity

  This is used within the DHT and is not exposed anywhere else. You should never have to deal with this directly and they will not be mentioned anywhere else in the documentation (except maybe the architecture reference).

- Identity

  This is what you as a user create and safeguard, use for publishing records, and the ids of which are used for lookups.

At this time, identity has two subtypes: local and card.

## Local identities

These are identities that are a file on your computer. If you have the file, you can publish and unpublish data for that identity.

This is less secure, mostly intended for use on servers or for people just trying things out, or people with use cases not requiring more security.

Using [`spagh`](./reference_spagh.md) you can:

- Create a local identity

  Run `spagh identity new-local me.spagh`

  This will create a new identity at `me.spagh` and print out the id of the identity.

  The id of the identity (like `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`) is used for lookups and can be used as a DNS name when suffixed with `.s` (ex: `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`).

- Get the id of a local identity

  Run `spagh identity show-local me.spagh`

  This will print the id of the identity again

## Card identities

Card is a misnomer today, this typicaly refers to hardware security devices like a Yubikey. Card identities store the private data on the card itself, rather than locally in a file.

Because card identities have the private data stored in secure hardware they can't be stolen by viruses or unauthorized computer access. Furthermore they typically have a password or PIN so even if the hardware is stolen they can't be used to impersonate you or delete your published data.

Any card that supports OpenPGP PC/SC and Ed25519 keys should work. The Yubikey 5 Nano is confirmed to work.

### Preparing the card

1. Make sure `pcscd` is running and your Yubikey is plugged in

2. Do `cargo install openpgp-card-tools` which installs `opgpcard`

3. Do `opgpcard list`, which should show your card with an id like `0006:123456789`

4. Install a new private key by doing `opgpcard admin --card 0006:123456789 generate cv25519` with the default `12345678` admin PIN (at the moment, only Ed25519 is supported so to get that you must use `cv25519`). Alternatively you can use GnuPG or Sequoia or something to generate a key then do `opgpcard admin --card XYZ import` instead, if you want to back up your identity. By the way, Sequoia is super cool and the people who work on it are equally amazing and amazingly nice.

### Confirming the card

- Show configured compatible cards

  Run `spagh identity list-cards`

  This will list the card identites, their ids, and the PC/SC id (like `0006:12341234`) used for command line arguments and configs.

## Referring to identities in configs and the command line

When running publishing commands or running servers that self-publish you need to refer to an identity not by its normal id but by the type and path or PC/SC ID. The command documentation also explains this, but to prepare you for when you encounter it:

- On the command line, you'll specify an identity like

  - `local ./me.spagh`

  - or `card 0006:12341234 5678` where `5678` is the PIN. Alternatively you can use `-` for the PIN and it will ask for you to type it in in the terminal.

- In configs you'll specify an identity like

  - `{"local": "./me.spagh"}`

  - or `{"card": {"pcsc_id": "0006:12341234", "pin": "5678"}}`
