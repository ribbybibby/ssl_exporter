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
  - [Table of Contents](#table-of-contents)
  - [Building](#building)
    - [Docker](#docker)
    - [Release process](#release-process)
  - [Usage](#usage)
  - [Metrics](#metrics)
  - [Configuration](#configuration)
    - [Configuration file](#configuration-file)
      - [&lt;module&gt;](#module)
      - [&lt;tls_config&gt;](#tls_config)
  - [Example Queries](#example-queries)
  - [Proxying](#proxying)
  - [Grafana](#grafana)

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

| Metric                  | Meaning                                                                             | Labels                                              |
| ----------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------- |
| ssl_cert_not_after      | The date after which the certificate expires. Expressed as a Unix Epoch Time.       | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou |
| ssl_cert_not_before     | The date before which the certificate is not valid. Expressed as a Unix Epoch Time. | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou |
| ssl_prober              | The prober used by the exporter to connect to the target. Boolean.                  | prober                                              |
| ssl_tls_connect_success | Was the TLS connection successful? Boolean.                                         |                                                     |
| ssl_tls_version_info    | The TLS version used. Always 1.                                                     | version                                             |

## Configuration

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

By default the exporter will make a TCP connection to the target. You can change
this to https by setting the module parameter:

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

### Configuration file

You can provide further module configuration by providing the path to a
configuration file with `--config.file`. The file is written in yaml format,
defined by the schema below.

```
modules: [<module>]
```

#### \<module\>

```
# The protocol over which the probe will take place (http, tcp)
prober: <prober_string>

# Configuration for TLS
[ tls_config: <tls_config> ]

# The specific probe configuration
[ https: <https_probe> ]
```

#### <tls_config>

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

#### <https_probe>

```
# HTTP proxy server to use to connect to the targets.
[ proxy_url: <string> ]
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

Number of certificates in the chain:

```
count(ssl_cert_not_after) by (instance, serial_no, issuer_cn)
```

Identify instances that have failed to create a valid SSL connection:

```
ssl_tls_connect_success == 0
```

## Proxying

The `https` prober supports the use of proxy servers discovered by the
environment variables `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`.

For instance:

    $ export HTTPS_PROXY=localhost:8888
    $ ./ssl_exporter

Or, you can set the `proxy_url` option in the module.

The latter takes precedence.

## Grafana

You can find a simple dashboard [here](grafana/dashboard.json) that tracks
certificate expiration dates and target connection errors.
