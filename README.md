# penguin-ms-suite-relay

Push relay for Microsoft Graph change notifications. Graph POSTs to the relay,
the relay forwards ids only over a WebSocket to the desktop client
(penguin-ms-suite). The relay holds no Graph tokens and never sees message
content. Design: `penguin-ms-suite/docs/relay-architecture.md` (option B:
client creates and renews the Graph subscription).

Go stdlib only (includes a minimal RFC 6455 server). In-memory hub; a small
JSON file keeps registered devices across restarts.

## Run

    RELAY_INVITE_SECRET=$(openssl rand -hex 16) docker compose up -d --build

Listens on port 8090 (published on `RELAY_BIND`, default 127.0.0.1). Put TLS in front (Nginx Proxy Manager, Caddy, or Cloudflare Tunnel) and
set `RELAY_TRUST_PROXY=true` when behind it. Graph requires a public HTTPS
`notificationUrl`.

Local, no Docker: `go run .` with `RELAY_STATE_FILE=./devices.json`.

Copy `.env.example` to `.env` and fill it in. The proxy terminates HTTPS and forwards to
`http://<RELAY_BIND address>:8090` with WebSocket support on.

## Config (env)

    RELAY_ADDR            listen address, default :8090
    RELAY_BIND            docker compose: host address port 8090 is published on, default 127.0.0.1
    RELAY_STATE_FILE      device store, default /data/devices.json
    RELAY_INVITE_SECRET   required Bearer token for POST /register; empty = open (warned)
    RELAY_TRUST_PROXY     true: client IP = rightmost X-Forwarded-For (for rate limits)

## API

    POST /register              (Authorization: Bearer <invite>)
                                -> {deviceId, deviceSecret, clientState}
    GET  /ws?deviceId=ID        Authorization: Bearer <deviceSecret>; WebSocket
    POST /hook/{deviceId}       Graph notifications + validationToken handshake
    POST /lifecycle/{deviceId}  Graph lifecycle notifications
    GET  /healthz

Deviation from the design doc: `register` also returns `clientState`. The
client must set it as `clientState` on its Graph subscription; the relay
drops notifications whose `clientState` differs. The device secret is stored
only as a SHA-256 hash.

Subscription example (client side, `includeResourceData:false`):

    notificationUrl:          https://RELAY/hook/DEVICE_ID
    lifecycleNotificationUrl: https://RELAY/lifecycle/DEVICE_ID
    clientState:              <clientState from /register>

WebSocket messages (server -> client):

    {"type":"hello","heartbeatSec":20}
    {"type":"heartbeat"}
    {"type":"message","chatId":"19:...","messageId":"..."}
    {"type":"resync"}   lifecycle "missed"
    {"type":"reauth"}   lifecycle "reauthorizationRequired" / "subscriptionRemoved"

The server also sends a WebSocket ping every 20 s; connections silent for 45 s
are closed. One connection per device: a new one evicts the old. A client that
cannot drain its queue is dropped and should reconnect and resync.

## Not done / caveats

- Lifecycle `validationTokens` (JWT signature check) are not verified; the
  `clientState` check is the only authenticity control.
- Graph limits and permissions in the design doc are still marked [verify];
  nothing here was tested against a real tenant.
- The penguin-ms-suite client (`src/relay.rs` `start()`, subscription
  create/renew) is not implemented.

## Test

    go test -race ./...
