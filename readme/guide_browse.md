# Guide: Browse the spaghettinuum

While the spaghettinuum is a replacement for all DNS uses, the most obvious use is viewing sites in your browser.

To do this you need to

1. Point your DNS resolver to a Spaghettinuum-DNS bridge for lookups

2. Set up HTTPS

## Lookups

There's a public resolver, [Antipasta](https://github.com/andrewbaxter/antipasta), which you can use for DNS and CLI lookups.

If you want to browse a `.s` site, set up your DNS to use Antipasta per Antipasta's readme.

### Host your own resolver

If you don't want to use the public node or don't trust me to keep it running, you can host your own node. See [the spagh-node reference](./reference_spagh_node.md) - you need to configure the node and resolver, and DNS bridge.

## HTTPS

Sites on the spaghettinuum have TLS certificates issued by [Certipasta](https://github.com/andrewbaxter/certipasta) so you'll also need to install the Certipasta root certificate. See that link for instructions.
