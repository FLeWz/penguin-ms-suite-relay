FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /relay . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /relay /relay
# Pre-owned dir so a fresh named volume is writable by the nonroot user.
COPY --from=build --chown=65532:65532 /data /data
VOLUME /data
ENV RELAY_ADDR=:8090 RELAY_STATE_FILE=/data/devices.json
EXPOSE 8090
USER nonroot
ENTRYPOINT ["/relay"]
