FROM golang:1.8.3-alpine3.6 as builder

ENV GOOS=linux GOARCH=amd64 GOPATH=/go

WORKDIR /go/src/github.com/ribbybibby/ssl_exporter

RUN apk --no-cache --quiet add git
RUN go get "github.com/prometheus/client_golang/prometheus" "gopkg.in/alecthomas/kingpin.v2" "github.com/sirupsen/logrus"

COPY . /go/src/github.com/ribbybibby/ssl_exporter

RUN go build

FROM alpine:3.6

RUN apk add --quiet --no-cache ca-certificates tzdata && rm -rf /var/cache/apk/*

COPY --from=builder /go/src/github.com/ribbybibby/ssl_exporter/ssl_exporter /ssl_exporter

ENTRYPOINT ["/ssl_exporter"]
