FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/moroz ./cmd/moroz

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && mkdir -p /config /var/log/moroz && chown 65532:65532 /var/log/moroz
COPY --from=builder /tmp/moroz /usr/local/bin/moroz
USER 65532:65532
EXPOSE 8080
# GET /healthz is served without credentials and stays internal (the ingress
# only forwards Santa's POST routes). Busybox wget tries plain HTTP first and
# falls back to TLS with the self-signed development certificate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD \
  port="${MOROZ_HTTP_ADDRESS##*:}"; port="${port:-8080}"; \
  wget -q -O /dev/null "http://127.0.0.1:${port}/healthz" \
  || wget -q -O /dev/null --no-check-certificate "https://127.0.0.1:${port}/healthz" \
  || exit 1
ENTRYPOINT ["/usr/local/bin/moroz"]
