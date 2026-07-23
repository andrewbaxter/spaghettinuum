# Antipasta

**NOTE** I disabled the DNS resolver component. For reference, it appears a public DNS server uses up around 1-2Tb of outbound data a month (~$300/mo at GCP) after being up for a month. Please consider setting up a private Spaghettinuum DNS resolver.

This is the bootstrap node for the [Spaghettinuum](https://github.com/andrewbaxter/spaghettinuum) network, also set up to act as a public resolver and DNS bridge. The DNS bridge forwards non-`.s` requests to a normal upstream DNS server, so you can use it seamlessly, although you may want to add a backup resolver.

<br/>

**Reference**

---

**DNS** `antipasta.isandrew.com`

**IPv4** `35.199.147.232`

**IPv6** `2600:1900:4040:485::`

**Spaghettinuum Node Identifier** `n_yryyyyyyybxx3rnepqdwa6s45z8qkc6x5xrceruxgy3q6rhm9rxzrrw1rwmbr`

**Spaghettinuum Node Port** `48390`

**Spaghettinuum Identifier** `yryyyyyyydz6tr57fdinhaaxb6okim5ihq6wiy6xagpckx7ekgwz3hsurcohs`

<br/>

# Set up DNS over TLS (port 853)

DNS over TLS requires both an IP and a server name which is used to circumvent the normal TLS verification process because TLS rules were established while ignoring everything other than web that could possibly need encryption.

In systemd-resolved you do this by specifying the DNS name after a `#` (server name indication, SNI)

**IPv4** `35.199.147.232#antipasta.isandrew.com`

**IPv6** `2600:1900:4040:485::#antipasta.isandrew.com`

# Set up UDP DNS (port 53)

You can set these up as you would any other DNS servers.

**IPv4** `35.199.147.232`

**IPv6** `2600:1900:4040:485::`

# Use it as a spaghettinuum resolver

Set the environment variable

```bash
export SPAGH_RESOLVERS="2600:1900:4040:485::=https://yryyyyyyydz6tr57fdinhaaxb6okim5ihq6wiy6xagpckx7ekgwz3hsurcohs.s"
```

# Bootstrap a spaghettinuum node

If you're setting up a node, use this bootstrap configuration:

```json
{
  "addr": "[2600:1900:4040:485::]:48390",
  "ident": "n_yryyyyyyybxx3rnepqdwa6s45z8qkc6x5xrceruxgy3q6rhm9rxzrrw1rwmbr"
}
```

(you may substitute the IPv4 address)
