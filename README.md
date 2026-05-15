# rocoon

Minimal Rust prototype for Cocoon client networking.

Current scope:

- Connect to a Cocoon proxy over TCP.
- Solve Cocoon TCP PoW challenge.
- Upgrade to TLS 1.3 with an ephemeral Ed25519 self-signed client certificate.
- Perform Cocoon frame/session handshake: `tcp.connect -> tcp.connected`.
- Encode Cocoon TL objects with `tl-proto`.
- Call `client.connectToProxy` and decode `client.connectedToProxy`.
- Authorize with `client.authorizeWithProxyShort`.
- Serve OpenAI-compatible HTTP on `127.0.0.1:9999`.
- Implement `/v1/models` through `client.getWorkerTypesV2`.
- Implement `/v1/chat/completions` and `/v1/completions` through `client.runQueryEx`.
- Collect streamed Cocoon answer parts before returning the local HTTP response.

Not implemented yet:

- TON root contract reading.
- Cocoon wallet deploy/top-up/register.
- RA-TLS/TEE quote verification.
- True local HTTP streaming; streamed Cocoon chunks are aggregated before the local response is sent.

Run:

```bash
cargo run
```

Config:

```toml
[network]
proxy_addr = "91.108.4.11:8888"
connect_timeout_secs = 5

[server]
listen_addr = "127.0.0.1:9999"

[client]
owner_address = "UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi"
secret = ""
min_config_version = 0

[request]
max_coefficient = 4000
max_tokens = 10000
timeout_secs = 120.0
```

`client.owner_address` is the Cocoon wallet contract address used by the C++
client in `client.connectToProxy`, not the external owner wallet address.

Use a different config file:

```bash
cargo run -- --config path/to/rocoon.toml
```

Environment overrides:

```bash
COCOON_PROXY_ADDR=91.108.4.11:8888 COCOON_OWNER_ADDRESS=UQ... COCOON_CLIENT_SECRET=... cargo run
```

API:

```bash
curl http://127.0.0.1:9999/v1/models
curl http://127.0.0.1:9999/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"Qwen/Qwen3-32B","messages":[{"role":"user","content":"Say hello"}],"max_tokens":8}'
```

When the proxy returns `auth: short`, `rocoon` uses `client.secret` or
`COCOON_CLIENT_SECRET` to call `client.authorizeWithProxyShort`.

When the proxy returns `auth: long`, `rocoon` stops before register/top-up,
because that requires on-chain TON transactions.

The server does not send TON transactions. `/v1/chat/completions` spends
Cocoon tokens through the existing authorized client balance.
