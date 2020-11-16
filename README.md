# SSL Certificate Exporter

Exports metrics for certificates collected from TCP probes, local files or
Kubernetes secrets. The metrics are labelled with fields from the certificate,
which allows for informational dashboards and flexible alert routing.

## Table of Contents

- [SSL Certificate Exporter](#ssl-certificate-exporter)
  - [Table of Contents](#table-of-contents)
  - [Building](#building)
    - [Docker](#docker)
    - [Release process](#release-process)
  - [Usage](#usage)
  - [Metrics](#metrics)
  - [Configuration](#configuration)
    - [TCP](#tcp)
    - [HTTPS](#https)
    - [File](#file)
    - [Kubernetes](#kubernetes)
  - [Configuration file](#configuration-file)
    - [&lt;module&gt;](#module)
    - [&lt;tls_config&gt;](#tls_config)
    - [&lt;https_probe&gt;](#https_probe)
    - [&lt;tcp_probe&gt;](#tcp_probe)
    - [&lt;kubernetes_probe&gt;](#kubernetes_probe)
  - [Example Queries](#example-queries)
  - [Peer Certificates vs Verified Chain Certificates](#peer-certificates-vs-verified-chain-certificates)
  - [Grafana](#grafana)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

## Building

    make
    ./ssl_exporter <flags>

Similarly to the blackbox_exporter, visiting
[http://localhost:9219/probe?target=example.com:443](http://localhost:9219/probe?target=example.com:443)
will return certificate metrics for example.com. The `ssl_probe_success`
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

## Usage

```
usage: ssl_exporter [<flags>]

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and
                                 --help-man).
      --web.listen-address=":9219"
                                 Address to listen on for web interface and telemetry.
      --web.metrics-path="/metrics"
                                 Path under which to expose metrics
      --web.probe-path="/probe"  Path under which to expose the probe endpoint
      --config.file=""           SSL exporter configuration file
      --log.level="info"         Only log messages with the given severity or above. Valid
                                 levels: [debug, info, warn, error, fatal]
      --log.format="logger:stderr"
                                 Set the log target and format. Example:
                                 "logger:syslog?appname=bob&local=7" or
                                 "logger:stdout?json=true"
      --version                  Show application version.
```

## Metrics

| Metric                         | Meaning                                                                                                          | Labels                                                                      | Probers    |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------- |
| ssl_cert_not_after             | The date after which a peer certificate expires. Expressed as a Unix Epoch Time.                                 | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                         | tcp, https |
| ssl_cert_not_before            | The date before which a peer certificate is not valid. Expressed as a Unix Epoch Time.                           | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                         | tcp, https |
| ssl_file_cert_not_after        | The date after which a certificate found by the file prober expires. Expressed as a Unix Epoch Time.             | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | file       |
| ssl_file_cert_not_before       | The date before which a certificate found by the file prober is not valid. Expressed as a Unix Epoch Time.       | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | file       |
| ssl_kubernetes_cert_not_after  | The date after which a certificate found by the kubernetes prober expires. Expressed as a Unix Epoch Time.       | namespace, secret, key, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubernetes |
| ssl_kubernetes_cert_not_before | The date before which a certificate found by the kubernetes prober is not valid. Expressed as a Unix Epoch Time. | namespace, secret, key, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubernetes |
| ssl_ocsp_response_next_update  | The nextUpdate value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_ocsp_response_produced_at  | The producedAt value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_ocsp_response_revoked_at   | The revocationTime value in the OCSP response. Expressed as a Unix Epoch Time                                    |                                                                             | tcp, https |
| ssl_ocsp_response_status       | The status in the OCSP response. 0=Good 1=Revoked 2=Unknown                                                      |                                                                             | tcp, https |
| ssl_ocsp_response_stapled      | Does the connection state contain a stapled OCSP response? Boolean.                                              |                                                                             | tcp, https |
| ssl_ocsp_response_this_update  | The thisUpdate value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_probe_success              | Was the probe successful? Boolean.                                                                               |                                                                             | all        |
| ssl_prober                     | The prober used by the exporter to connect to the target. Boolean.                                               | prober                                                                      | all        |
| ssl_tls_version_info           | The TLS version used. Always 1.                                                                                  | version                                                                     | tcp, https |
| ssl_verified_cert_not_after    | The date after which a certificate in the verified chain expires. Expressed as a Unix Epoch Time.                | chain_no, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou               | tcp, https |
| ssl_verified_cert_not_before   | The date before which a certificate in the verified chain is not valid. Expressed as a Unix Epoch Time.          | chain_no, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou               | tcp, https |

## Configuration

### TCP

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

### HTTPS

By default the exporter will make a TCP connection to the target. This will be
suitable for most cases but if you want to take advantage of http proxying you
can use a HTTPS client by setting the `https` module parameter:

```yml
scrape_configs:
  - job_name: "ssl"
    metrics_path: /probe
    params:
      module: ["https"] # <-----
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
        replacement: 127.0.0.1:9219
```

This will use proxy servers discovered by the environment variables `HTTP_PROXY`,
`HTTPS_PROXY` and `ALL_PROXY`. Or, you can set the `proxy_url` option in the module
configuration.

The latter takes precedence.

### File

The `file` prober exports `ssl_file_cert_not_after` and
`ssl_file_cert_not_before` for PEM encoded certificates found in local files.

Files local to the exporter can be scraped by providing them as the target
parameter:

```
curl "localhost:9219/probe?module=file&target=/etc/ssl/cert.pem"
```

The target parameter supports globbing (as provided by the
[doublestar](https://github.com/bmatcuk/doublestar) package),
which allows you to capture multiple files at once:

```
curl "localhost:9219/probe?module=file&target=/etc/ssl/**/*.pem"
```

One specific usage of this prober could be to run the exporter as a DaemonSet in
Kubernetes and then scrape each instance to check the expiry of certificates on
each node:

```yml
scrape_configs:
  - job_name: "ssl-kubernetes-file"
    metrics_path: /probe
    params:
      module: ["file"]
      target: ["/etc/kubernetes/**/*.crt"]
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - source_labels: [__address__]
        regex: ^(.*):(.*)$
        target_label: __address__
        replacement: ${1}:9219
```

### Kubernetes

The `kubernetes` prober exports `ssl_kubernetes_cert_not_after` and
`ssl_kubernetes_cert_not_before` for PEM encoded certificates found in secrets
of type `kubernetes.io/tls`.

Provide the namespace and name of the secret in the form `<namespace>/<name>` as
the target:

```
curl "localhost:9219/probe?module=kubernetes&target=kube-system/secret-name"
```

Both the namespace and name portions of the target support glob matching (as provided by the
[doublestar](https://github.com/bmatcuk/doublestar) package):

```
curl "localhost:9219/probe?module=kubernetes&target=kube-system/*"

```

```
curl "localhost:9219/probe?module=kubernetes&target=*/*"

```

The exporter retrieves credentials and context configuration from the following
sources in the following order:

- The `kubeconfig` path in the module configuration
- The `$KUBECONFIG` environment variable
- The default configuration file (`$HOME/.kube/config`)
- The in-cluster environment, if running in a pod

## Configuration file

You can provide further module configuration by providing the path to a
configuration file with `--config.file`. The file is written in yaml format,
defined by the schema below.

```
modules: [<module>]
```

### \<module\>

```
# The type of probe (https, tcp, file, kubernetes)
prober: <prober_string>

# How long the probe will wait before giving up.
[ timeout: <duration> ]

# Configuration for TLS
[ tls_config: <tls_config> ]

# The specific probe configuration
[ https: <https_probe> ]
[ tcp: <tcp_probe> ]
[ kubernetes: <kubernetes_probe> ]
```

### <tls_config>

```
# Disable target certificate validation.
[ insecure_skip_verify: <boolean> | default = false ]

# The CA cert to use for the targets.
[ ca_file: <filename> ]

# The client cert file for the targets.
[ cert_file: <filename> ]

# The client key file for the targets.
[ key_file: <filename> ]

# Used to verify the hostname for the targets.
[ server_name: <string> ]
```

### <https_probe>

```
# HTTP proxy server to use to connect to the targets.
[ proxy_url: <string> ]
```

### <tcp_probe>

```
# Use the STARTTLS command before starting TLS for those protocols that support it (smtp, ftp, imap)
[ starttls: <string> ]
```

### <kubernetes_probe>

```
# The path of a kubeconfig file to configure the probe
[ kubeconfig: <string> ]
```

## Example Queries

Certificates that expire within 7 days:

```
ssl_cert_not_after - time() < 86400 * 7
```

Wildcard certificates that are expiring:

```
ssl_cert_not_after{cn=~"\*.*"} - time() < 86400 * 7
```

Certificates that expire within 7 days in the verified chain that expires
latest:

```
ssl_verified_cert_not_after{chain_no="0"} - time() < 86400 * 7
```

Number of certificates presented by the server:

```
count(ssl_cert_not_after) by (instance)
```

Identify failed probes:

```
ssl_probe_success == 0
```

## Peer Certificates vs Verified Chain Certificates

Metrics are exported for the `NotAfter` and `NotBefore` fields for peer
certificates as well as for the verified chain that is
constructed by the client.

The former only includes the certificates that are served explicitly by the
target, while the latter can contain multiple chains of trust that are
constructed from root certificates held by the client to the target's server
certificate.

This has important implications when monitoring certificate expiry.

For instance, it may be the case that `ssl_cert_not_after` reports that the root
certificate served by the target is expiring soon even though clients can form
another, much longer lived, chain of trust using another valid root certificate
held locally. In this case, you may want to use `ssl_verified_cert_not_after` to
alert on expiry instead, as this will contain the chain that the client actually
constructs:

```
ssl_verified_cert_not_after{chain_no="0"} - time() < 86400 * 7
```

Each chain is numbered by the exporter in reverse order of expiry, so that
`chain_no="0"` is the chain that will expire the latest. Therefore the query
above will only alert when the chain of trust between the exporter and the
target is truly nearing expiry.

It's very important to note that a query of this kind only represents the chain
of trust between the exporter and the target. Genuine clients may hold different
root certs than the exporter and therefore have different verified chains of
trust.

## Grafana

You can find a simple dashboard [here](grafana/dashboard.json) that tracks
certificate expiration dates and target connection errors.
