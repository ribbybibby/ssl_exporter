# SSL Certificate Exporter

The [blackbox_exporter](https://github.com/prometheus/blackbox_exporter) allows
you to test the expiry date of a certificate as part of its HTTP(S) probe -
which is great. It doesn't, however, tell you which certificate in the chain is
nearing expiry or give you any other information that might be useful when
sending alerts.

For instance, there's a definite value in knowing, upon first receiving an
alert, if it's a certificate you manage directly or one further up the chain.
It's also not always necessarily clear from the address you're polling what kind
of certificate renewal you're looking at. Is it a Let's Encrypt, in which case
it should be handled by automation? Or your organisation's wildcard? Maybe the
domain is managed by a third-party and you need to submit a ticket to get it
renewed.

Whatever it is, the SSL exporter gives you visibility over those dimensions at
the point at which you receive an alert. It also allows you to produce more
meaningful visualisations and consoles.

## Table of Contents

- [SSL Certificate Exporter](#ssl-certificate-exporter)
  - [Building](#building)
  - [Docker](#docker)
  - [Flags](#flags)
  - [Metrics](#metrics)
  - [Prometheus](#prometheus)
    - [Configuration](#configuration)
    - [Targets](#targets)
      - [Valid targets](#valid-targets)
      - [Invalid targets](#invalid-targets)
    - [Example Queries](#example-queries)
  - [Client authentication](#client-authentication)
  - [Proxying](#proxying)
  - [Limitations](#limitations)
  - [Acknowledgements](#acknowledgements)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

## Building

    make
    ./ssl_exporter <flags>

Similarly to the blackbox_exporter, visiting
[http://localhost:9219/probe?target=example.com:443](http://localhost:9219/probe?target=example.com:443)
will return certificate metrics for example.com. The `ssl_tls_connect_success`
metric indicates if the probe has been successful.

### Docker

    docker pull ribbybibby/ssl-exporter
    docker run -p 9219:9219 ribbybibby/ssl-exporter:latest <flags>

### Release process

- Update the `VERSION` file in this repository and commit to master
- [This github action](.github/workflows/release.yaml) will add a changelog and
  upload binaries in response to a release being created in Github
- Dockerhub will build and tag a new container image in response to tags of the
  format `/^v[0-9.]+$/`

## Flags

    ./ssl_exporter --help

- **`--tls.insecure`:** Skip certificate verification (default false). This is
  insecure but does allow you to collect metrics in the case where a certificate
  has expired. That being said, I feel that it's more important to catch
  verification failures than it is to identify an expired certificate,
  especially as the former includes the latter.
- **`--tls.cacert`:** Provide the path to an alternative bundle of root CA
  certificates. By default the exporter will use the host's root CA set.
- **`--tls.client-auth`:** Enable client authentication (default false). When
  enabled the exporter will present the certificate and key configured by
  `--tls.cert` and `tls.key` to the other side of the connection.
- **`--tls.cert`:** The path to a local certificate for client authentication
  (default "cert.pem"). Only used when `--tls.client-auth` is toggled on.
- **`--tls.key`:** The path to a local key for client authentication (default
  "key.pem"). Only used when `--tls.client-auth` is toggled on.
- **`--web.listen-address`:** The port (default ":9219").
- **`--web.metrics-path`:** The path metrics are exposed under (default
  "/metrics")
- **`--web.probe-path`:** The path the probe endpoint is exposed under (default
  "/probe")

## Metrics

| Metric                  | Meaning                                                                             | Labels                                              |
| ----------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------- |
| ssl_cert_not_after      | The date after which the certificate expires. Expressed as a Unix Epoch Time.       | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou |
| ssl_cert_not_before     | The date before which the certificate is not valid. Expressed as a Unix Epoch Time. | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou |
| ssl_client_protocol     | The protocol used by the exporter to connect to the target. Boolean.                | protocol                                            |
| ssl_tls_connect_success | Was the TLS connection successful? Boolean.                                         |                                                     |
| ssl_tls_version_info    | The TLS version used. Always 1.                                                     | version                                             |

## Prometheus

### Configuration

Just like with the blackbox_exporter, you should pass the targets to a single
instance of the exporter in a scrape config with a clever bit of relabelling.
This allows you to leverage service discovery and keeps configuration
centralised to your Prometheus config.

```yml
scrape_configs:
  - job_name: "ssl"
    metrics_path: /probe
    static_configs:
      - targets:
          - example.com:443
          - prometheus.io:443
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219 # SSL exporter.
```

### Targets

The exporter uses the provided uri to decide which client (http or tcp) to use
when connecting to the target. The uri must contain either a protocol scheme
(`https://`), a port (`:443`), or both (`https://example.com:443`).

If the `https://` scheme is provided then the exporter will use a http client to
connect to the target. This allows you to take advantage of some features not
available when using tcp, like host-based proxying. The exporter doesn't
understand any other L7 protocols, so it will produce an error for others, like
`ldaps://` or `ftps://`.

If there's only a port, then a tcp client is used to make the TLS connection.
This should allow you to connect to any TLS target, regardless of L7 protocol.

If neither are given, the exporter assumes a https connection on port `443` (the
most common case).

#### Valid targets

- `https://example.com`
- `https://example.com:443`
- `example.com:443`
- `example.com:636`
- `example.com`

#### Invalid targets

- `ldaps://example.com`
- `ldaps://example.com:636`

### Example Queries

Certificates that expire within 7 days:

```
ssl_cert_not_after - time() < 86400 * 7
```

Wildcard certificates that are expiring:

```
ssl_cert_not_after{cn=~"\*.*"} - time() < 86400 * 7
```

Number of certificates in the chain:

```
count(ssl_cert_not_after) by (instance, serial_no, issuer_cn)
```

Identify instances that have failed to create a valid SSL connection:

```
ssl_tls_connect_success == 0
```

## Client authentication

The exporter optionally supports client authentication, which can be toggled on
by providing the `--tls.client-auth` flag. By default, it will use the host
system's root CA bundle and attempt to use `./cert.pem` and `./key.pem` as the
client certificate and key, respectively. You can override these defaults with
`--tls.cacert`, `--tls.cert` and `--tls.key`.

If you do enable client authentication, keep in mind that the certificate will
be passed to all targets, even those that don't necessarily require client
authentication. I'm not sure what the implications of that are but I think you'd
probably want to avoid passing a certificate to an unrelated server.

Also, if you want to scrape targets with different client certificate
requirements, you'll need to run different instances of the exporter for each.
This seemed like a better approach than overloading the exporter with the
ability to pass different certificates per-target.

## Proxying

The https client used by the exporter supports the use of proxy servers
discovered by the environment variables `HTTP_PROXY`, `HTTPS_PROXY` and
`ALL_PROXY`.

For instance:

    $ export HTTPS_PROXY=localhost:8888
    $ ./ssl_exporter

In order to use the https client, targets must be provided to the exporter with
the protocol in the uri (`https://<host>:<optional port>`).

## Grafana

You can find a simple dashboard [here](grafana/dashboard.json) that tracks
certificate expiration dates and target connection errors.

## Acknowledgements

The overall structure and implementation of this exporter is based on the
[consul_exporter](https://github.com/prometheus/consul_exporter). The probing
functionality borrows from the blackbox_exporter.
