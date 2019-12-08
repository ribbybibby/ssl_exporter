FROM golang:1.13-stretch AS build

ADD . /tmp/ssl_exporter

RUN cd /tmp/ssl_exporter && \
    echo "ssl:*:100:ssl" > group && \
    echo "ssl:*:100:100::/:/ssl_exporter" > passwd && \
    make


FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /tmp/ssl_exporter/group \
    /tmp/ssl_exporter/passwd \
    /etc/
COPY --from=build /tmp/ssl_exporter/ssl_exporter /

USER ssl:ssl
EXPOSE 9219/tcp
ENTRYPOINT ["/ssl_exporter"]
