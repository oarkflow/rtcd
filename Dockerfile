# Build from a checkout (go.mod replaces pion/ice with a fork, so `go install …@version` does not work).
FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rtcd ./cmd/rtcd && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rtcd /rtcd
# A data directory the unprivileged user owns, so a named volume mounted at /data starts writable.
COPY --from=build --chown=65532:65532 /out/data /data
# Signaling (HTTP/WebSocket). Media uses the UDP range set by udp_port_min/udp_port_max in rtcd.bcl:
# publish exactly that range, and set public_ips when the host is behind NAT.
EXPOSE 8480
USER nonroot
ENTRYPOINT ["/rtcd", "-config", "/etc/rtcd/rtcd.bcl"]
