FROM alpine:3.15 as build
RUN apk --update add ca-certificates

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ssl_exporter /

USER 10001

EXPOSE 9219/tcp
ENTRYPOINT ["/ssl_exporter"]
