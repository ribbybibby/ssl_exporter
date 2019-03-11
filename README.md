# SSL Certificate Exporter

The [blackbox_exporter](https://github.com/prometheus/blackbox_exporter) allows you to test the expiry date of a certificate as part of its HTTP(S) probe - which is great. It doesn't, however, tell you which certificate in the chain is nearing expiry or give you any other information that might be useful when sending alerts. 

For instance, there's a definite value in knowing, upon first receiving an alert, if it's a certificate you manage directly or one further up the chain. It's also not always necessarily clear from the address you're polling what kind of certificate renewal you're looking at. Is it a Let's Encrypt, in which case it should be handled by automation? Or your organisation's wildcard? Maybe the domain is managed by a third-party and you need to submit a ticket to get it renewed. 

Whatever it is, the SSL exporter gives you visibility over those dimensions at the point at which you receive an alert. It also allows you to produce more meaningful visualisations and consoles.

## Building
    make
    ./ssl_exporter <flags>

Similarly to the blackbox_exporter, visiting [http://localhost:9219/probe?target=https://example.com](http://localhost:9219/probe?target=https://example.com) will return certificate metrics for example.com. The ```ssl_https_connect_success``` metric indicates if the probe has been successful.

## Docker
    docker pull ribbybibby/ssl-exporter
    docker run -p 9219:9219 ssl-exporter:latest <flags>

## Flags
    ./ssl_exporter --help
 * __`--tls.insecure`:__ Skip certificate verification (default false). This is insecure but does allow you to collect metrics in the case where a certificate has expired. That being said, I feel that it's more important to catch verification failures than it is to identify an expired certificate, especially as the former includes the latter.
 * __`--tls.cacert`:__ Provide the path to an alternative bundle of root CA certificates. By default the exporter will use the host's root CA set.
 * __`--tls.client-auth`:__ Enable client authentication (default false). When enabled the exporter will present the certificate and key configured by `--tls.cert` and `tls.key` to the other side of the connection.
 * __`--tls.cert`:__ The path to a local certificate for client authentication (default "cert.pem"). Only used when `--tls.client-auth` is toggled on.
 * __`--tls.key`:__ The path to a local key for client authentication (default "key.pem"). Only used when `--tls.client-auth` is toggled on.
 * __`--web.listen-address`:__ The port (default ":9219").
 * __`--web.metrics-path`:__ The path metrics are exposed under (default "/metrics")
 * __`--web.probe-path`:__ The path the probe endpoint is exposed under (default "/probe")

## Metrics
Metrics are exported for each certificate in the chain individually. All of the metrics are labelled with the Issuer's Common Name and the Serial ID, which is pretty much a unique identifier.

I considered having a series for each ```ssl_cert_subject_alternative_*``` value but these labels aren't actually very cardinal, considering the most frequently they'll change is probably every three months, which is longer than most metric retention times anyway. Joining them within commas as I've done allows for easy parsing and relabelling.

| Metric | Meaning | Labels |
| ------ | ------- | ------ |
| ssl_cert_not_after | The date after which the certificate expires. Expressed as a Unix Epoch Time. | issuer_cn, serial_no |
| ssl_cert_not_before | The date before which the certificate is not valid. Expressed as a Unix Epoch Time. | issuer_cn, serial_no |
| ssl_cert_subject_common_name | The common name of the certificate. Always has a value of 1 | issuer_cn, serial_no, subject_cn |
| ssl_cert_subject_alternative_dnsnames | The subject alternative names (if any). Always has a value of 1 | issuer_cn, serial_no, dnsnames |
| ssl_cert_subject_alternative_emails | The subject alternative email addresses (if any). Always has a value of 1 | issuer_cn, serial_no, emails |
| ssl_cert_subject_alternative_ips | The subject alternative IP addresses (if any). Always has a value of 1 | issuer_cn, serial_no, ips |
| ssl_cert_subject_organization_units | The subject organization names (if any). Always has a value of 1. | issuer_cn, serial_no, subject_ou |
| ssl_https_connect_success | Was the HTTPS connection successful? Boolean. | |

## Prometheus
### Configuration
Just like with the blackbox_exporter, you should pass the targets to a single instance of the exporter in a scrape config with a clever bit of relabelling. This allows you to leverage service discovery and keeps configuration centralised to your Prometheus config.
```yml
scrape_configs:
  - job_name: 'ssl'
    metrics_path: /probe
    static_configs:
      - targets:
        - https://example.com
        - https://prometheus.io
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219  # SSL exporter.
```
### Example Queries
Certificates that expire within 7 days, with Subject Common Name and Subject Alternative Names joined on:
    
    ((ssl_cert_not_after - time() < 86400 * 7) * on (instance,issuer_cn,serial_no) group_left (dnsnames) ssl_cert_subject_alternative_dnsnames) * on (instance,issuer_cn,serial_no) group_left (subject_cn) ssl_cert_subject_common_name


Only return wildcard certificates that are expiring:
  
    ((ssl_cert_not_after - time() < 86400 * 7) * on (instance,issuer_cn,serial_no) group_left (subject_cn) ssl_cert_subject_common_name{subject_cn=~"\\*.*"})


Number of certificates in the chain:
  
    count(ssl_cert_subject_common_name) by (instance)

Identify instances that have failed to create a valid SSL connection:

    ssl_https_connect_success == 0

## Client authentication
The exporter optionally supports client authentication, which can be toggled on by providing the `--tls.client-auth` flag. By default, it will use the host system's root CA bundle and attempt to use `./cert.pem` and `./key.pem` as the client certificate and key, respectively. You can override these defaults with `--tls.cacert`, `--tls.cert` and `--tls.key`.

If you do enable client authentication, keep in mind that the certificate will be passed to all targets, even those that don't necessarily require client authentication. I'm not sure what the implications of that are but I think you'd probably want to avoid passing a certificate to an unrelated server.

Also, if you want to scrape targets with different client certificate requirements, you'll need to run different instances of the exporter for each. This seemed like a better approach than overloading the exporter with the ability to pass different certificates per-target.

## Limitations
I've only exported a subset of the information you could extract from a certificate. It would be simple to add more, for instance organisational information, if there's a need.

## Acknowledgements
The overall structure and implementation of this exporter is based on the [consul_exporter](https://github.com/prometheus/consul_exporter). The probing functionality borrows from the blackbox_exporter.
