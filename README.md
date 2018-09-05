# sōzu-acme

sozu-acme is a configuration tool for the
[sōzu HTTP reverse proxy](https://github.com/sozu-proxy/sozu)
that automates certificate requests from
[Let's Encrypt](https://letsencrypt.org/) or other
[ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-07) enabled
certificate authorities.

This tool is in beta right now, don't hesitate to test it and report issues.

## Usage

```
sozu-acme --config      /path/to/sozu/config.toml # configuration file for sozu
          --certificate /path/to/cert.pem         # path to store new certificate
          --key         /path/to/key.pem          # path to store the key
          --chain       /path/to/chain.pem        # path to store the certificate chain
          --domain      example.com               # domain name for which the certificate will be generated
          --email       example@example.com       # registration email
          --id          app_example               # application id for sozu
          --http        1.2.3.4:80                # frontend HTTP address (for the challenge)
          --https       1.2.3.4:443               # frontend HTTPS address (for the challenge)
```

this tool will perform the following actions:

- contact Let's Encrypt
- retrieve the challenge data
- launch a web server for the HTTP challenge
- configure sōzu to redirect the challenge request to that web server
- start the HTTP challenge validation
- if the challenge was successful, write the certificate, chain and key to the specified paths
- remove the challenge web server from sōzu's configuration
