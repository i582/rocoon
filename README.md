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
- Read Cocoon wallet/client-contract state from TON liteservers.
- Send owner control transactions through the Cocoon wallet with CLI commands.
- Sweep the closed Cocoon wallet balance back to the owner wallet with the CLI.

Workspace layout:

- `rocoon-protocol`: Cocoon TL objects, encoders, and decoders.
- `rocoon-contract`: TLB-backed Rust types for Cocoon smart-contract storage
  and message bodies.
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
- Cocoon wallet top-up/register.
- RA-TLS/TEE quote verification.
- True local HTTP streaming; streamed Cocoon chunks are aggregated before the local response is sent.

Run:

```bash
cargo run -- start
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

`[ton]` uses TON liteservers to fill `/stats.wallet.*`,
`/stats.client_contract.*`, and the masterchain seqno used for the read. The
same liteclient path sends signed external messages for explicit CLI controls.
It does not top up or register contracts. Omit `config_path` to use
rocoon's embedded mainnet config, or the `ton-rs` default when `mainnet = false`.

Use a different config file:

```bash
cargo run -- --config path/to/rocoon.toml start
```

CLI one-shot controls:

```bash
cargo run -- request-withdraw
cargo run -- close
cargo run -- withdraw --client-contract <client-contract-address>
cargo run -- withdraw --to <destination-address> --reserve-nanotons 100000000
```

`request-withdraw` sends `owner_client_withdraw` from the client contract to the
Cocoon wallet. `close` sends `owner_client_request_refund`. `withdraw` or
`sweep` sends the sweepable Cocoon wallet balance to `client.owner_address` or
`--to`. If proxy discovery cannot resolve an already closed client contract,
`rocoon` first tries the locally cached client contract from `.rocoon-state`;
if there is no matching cache, pass the contract address with `--client-contract`.
When the proxy reports that the cached client contract is closing or closed,
`start` records that in `.rocoon-state` and tells you to generate a new
`client.node_wallet_key` before starting again.

Environment overrides:

```bash
COCOON_PROXY_ADDR=91.108.4.11:8888 COCOON_OWNER_ADDRESS=<owner-wallet-address> COCOON_NODE_WALLET_KEY=... COCOON_CLIENT_SECRET=... ROCOON_TON_READONLY_ENABLED=true cargo run -- start
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
When `[ton].readonly_enabled` is true, it also returns TON wallet balance,
seqno, account state, last transaction logical time, client-contract state,
stake/balance/tokens fields, and masterchain seqno.

When the proxy returns `auth: short`, `rocoon` uses `client.secret` or
`COCOON_CLIENT_SECRET` to call `client.authorizeWithProxyShort`.

When the proxy returns `auth: long`, `rocoon` stops before register/top-up,
because that requires on-chain TON transactions.

`/v1/chat/completions` spends Cocoon tokens through the existing authorized
client balance. TON control transactions are available only through the CLI
commands above.

## License

rocoon is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in rocoon by you, as defined in the Apache-2.0 license, shall be dually licensed
as above, without any additional terms or conditions.
