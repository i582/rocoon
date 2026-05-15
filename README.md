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
- Expose local runtime statistics through `/stats`, `/jsonstats`, and `/v1/stats`.
- Read Cocoon wallet balance/seqno from TON liteservers without sending transactions.

Workspace layout:

- `rocoon-protocol`: Cocoon TL objects, encoders, and decoders.
- `rocoon-transport`: reusable Cocoon proxy transport stack: TCP PoW, RA-TLS,
  `tcp.query`, `tcp.packet`, ping/pong, and `runQueryEx` answer aggregation.
- `rocoon-client`: high-level Cocoon client API: proxy authorization, model
  discovery, and completion requests.
- `rocoon-openai-server`: local OpenAI-compatible HTTP bridge over
  `rocoon-client`.
- `rocoon`: thin binary that loads config, connects the client, and starts the
  HTTP bridge.

Not implemented yet:

- TON root contract reading.
- Cocoon wallet deploy/top-up/register.
- RA-TLS/TEE quote verification.
- True local HTTP streaming; streamed Cocoon chunks are aggregated before the local response is sent.

Run:

```bash
cargo run
```

Checks:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings
cargo check --workspace
cargo test --workspace
```

Config:

```toml
[network]
proxy_addr = "91.108.4.11:8888"
connect_timeout_secs = 5

[server]
listen_addr = "127.0.0.1:9999"

[client]
owner_address = "<external-owner-wallet-address>"
node_wallet_key = "<base64-32-byte-node-wallet-private-key>"
secret = ""
min_config_version = 0

[request]
max_coefficient = 4000
max_tokens = 10000
timeout_secs = 120.0

[ton]
readonly_enabled = true
mainnet = true
query_timeout_millis = 5000
# config_path = "/path/to/global.config.json"
# root_contract_address = "<cocoon-root-contract-address>"
```

`client.owner_address` matches the C++ client config: it is the external owner
wallet address. `rocoon` derives the Cocoon wallet smart-contract address from
`client.owner_address` and `client.node_wallet_key`, then sends that derived
contract address in `client.connectToProxy`.

`[ton]` is read-only. It uses TON liteservers to fill `/stats.wallet.balance`,
`/stats.wallet.seqno`, account state, last transaction logical time, and the
masterchain seqno used for the read. It does not deploy contracts, top up
wallets, or send external messages. Omit `config_path` to use the built-in
mainnet/testnet config from `ton-rs`.

Use a different config file:

```bash
cargo run -- --config path/to/rocoon.toml
```

Environment overrides:

```bash
COCOON_PROXY_ADDR=91.108.4.11:8888 COCOON_OWNER_ADDRESS=<owner-wallet-address> COCOON_NODE_WALLET_KEY=... COCOON_CLIENT_SECRET=... ROCOON_TON_READONLY_ENABLED=true cargo run
```

API:

```bash
curl http://127.0.0.1:9999/v1/models
curl http://127.0.0.1:9999/stats
curl http://127.0.0.1:9999/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"Qwen/Qwen3-32B","messages":[{"role":"user","content":"Say hello"}],"max_tokens":8}'
```

`/stats` returns locally observed request counters, token usage from Cocoon
`final_info`, worker response `usage.total_cost`, proxy/debug strings from the
last request, proxy connection metadata, and the derived Cocoon wallet address.
When `[ton].readonly_enabled` is true, it also returns read-only TON wallet
balance, seqno, account state, last transaction logical time, and masterchain
seqno.

When the proxy returns `auth: short`, `rocoon` uses `client.secret` or
`COCOON_CLIENT_SECRET` to call `client.authorizeWithProxyShort`.

When the proxy returns `auth: long`, `rocoon` stops before register/top-up,
because that requires on-chain TON transactions.

The server does not send TON transactions. `/v1/chat/completions` spends
Cocoon tokens through the existing authorized client balance.

## License

rocoon is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in rocoon by you, as defined in the Apache-2.0 license, shall be dually licensed
as above, without any additional terms or conditions.
