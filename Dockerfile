FROM alpine:3.15 as build
RUN apk --update add ca-certificates
RUN echo "ssl:*:100:ssl" > /tmp/group && \
    echo "ssl:*:100:100::/:/ssl_exporter" > /tmp/passwd


FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /tmp/group \
    /tmp/passwd \
    /etc/
COPY ssl_exporter /

USER ssl:ssl
EXPOSE 9219/tcp
ENTRYPOINT ["/ssl_exporter"]
