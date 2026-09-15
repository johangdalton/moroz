FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/moroz ./cmd/moroz

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && mkdir -p /config /var/log/moroz && chown 65532:65532 /var/log/moroz
COPY --from=builder /tmp/moroz /usr/local/bin/moroz
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/moroz"]
