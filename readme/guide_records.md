# Guide: Records

Data published in spaghettinuum is in key-value form.

- The key is a list of any valid utf-8 strings. This is typically a path followed by a record type. For DNS-equivalent records the path would correspond to the subdomains, and the DNS record type would be the final segment.

- The value is any JSON value

These are arbitrary, but there are some predefined records and some suggestions/conventions for making your own record types.

## Predefined records

- Delegate records

  These instruct the client to repeat the query with a modified path. They're intended to be used to delegate subtrees to other systems or organizations.

  The key is a list of path segments with a final `delegate` segment.

  The value is in [this format](./schemas/record_delegate.schema.json).

  A querying client should query for delegate records for all non-empty prefixes of their request path. Replace the prefix of the path from the shortest match with the record result, then repeat the query. If there are no delegate records, handle the response as usual.

- DNS equivalent A records, with data in [this format](./schemas/record_dns_a.schema.json)

- DNS equivalent AAAA records, with data in [this format](./schemas/record_dns_aaaa.schema.json)

- DNS equivalent TXT records, with data in [this format](./schemas/record_dns_txt.schema.json)

- DNS equivalent MX records, with data in [this format](./schemas/record_dns_mx.schema.json)

- TLS certificate records, with data in [this format](./schemas/record_tls_certs.schema.json)

  For spaghettinuum-compatible HTTP clients, TLS certificates should be requested along with normal records. If present, the TLS certificate should be trusted for the associated identity/domain, regardless of certificate chains, etc.

- SSH host key records, with data in [this format](./schemas/record_ssh_hostkeys.schema.json)

  For spaghettinuum-compatible SSH clients, host keys should be requested along with normal records when looking up an SSH host. If present, the SSH host keys should be trusted. A local host key store is not necessary (the resolver cache should be enough).

## Conventions

These are rough conventions, but hopefully are generally applicable.

- All records, clients, should request and follow delegate records

- All records should support arbitrary key prefixes, to allow a single identity to publish multiple parallel services, data, etc.

- All records should allow multiple values. The meaning depends on the use case, but typically it would be one of the following:

  - All values are valid, and any one randomly selected value should be used. For services, this allows for client-controlled load balancing, and if one value fails to respond the client can try another value for client-controlled failover.

  - All values are valid and should be used together, for remote-initiated information. Things like TLS certificates and SSH host keys, where the remote end may respond with any of the values when contacted (this allows for downtime-less value rotations, or pools of servers where each server has a different certificate, etc.)
