# Guide: Identities

Spaghettinuum identities are like `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r`.

Identities serve as an address for looking up information published by the identity, and can be used as a DNS name when suffixed with `.s` (ex: `yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s`) if the identity published DNS-wrapper records.

Each identity has a secret, required to use the identity. There are two types of secrets supported at the moment: local (file-based) and smartcard (ex: Yubikey) identities.

(Note: there are also "node identities" that are used within the DHT and is not exposed anywhere else. You should never have to deal with these directly and they will not be mentioned anywhere else in the documentation (except maybe the architecture reference). You can identify these identities because they start with `n_`)

## Local identity secrets

A local identity secret is a file containing cryptographic information on the identity. If you have the file, you can publish and unpublish data for that identity.

Since this is easy to lose/expose, it's mostly intended for use on servers or for people just trying things out.

Using [`spagh`](./reference_spagh.md) you can:

- Create a local identity secret

  Run `spagh identity new-local my.ident`

  This will create a new identity at `my.ident` and print out the id of the identity.

- Get the id of a local identity secret

  Run `spagh identity show-local my.ident`

  This will print the id of the identity again

## Card identity secrets

Card is a misnomer today - this typicaly refers to hardware security devices like a Yubikey. Card identities store the private data on the card itself, rather than locally in a file.

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

  This will list the card identites and the PC/SC id (like `0006:12341234`) used for command line arguments and configs.

### Troubleshooting

- Make sure your Yubikey isn't plugged into the USB 2 socket upside down

## Referring to identities in configs and the command line

When running publishing commands or running servers that self-publish you need to refer to an identity not by its normal id but by the type and path or PC/SC ID. The command documentation also explains this, but to prepare you for when you encounter it:

- On the command line, you'll specify an identity like

  - `local ./my.ident`

  - or `card 0006:12341234 5678` where `5678` is the PIN. Alternatively you can use `-` for the PIN and it will ask for you to type it in in the terminal.

- In configs you'll specify an identity like

  - `{"local": "./my.ident"}`

  - or `{"card": {"pcsc_id": "0006:12341234", "pin": "5678"}}`
