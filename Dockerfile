FROM        quay.io/prometheus/busybox:latest

COPY ssl_exporter /bin/ssl_exporter

ENTRYPOINT ["/bin/ssl_exporter"]
