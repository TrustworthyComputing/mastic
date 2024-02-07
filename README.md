<h1 align="center">Mastic: Private Weighted Heavy-Hitters and Attribute-Based Metrics
  <a href="https://github.com/TrustworthyComputing/mastic/actions/workflows/ci-build.yml"><img src="https://github.com/TrustworthyComputing/mastic/workflows/ci-build/badge.svg"></a>
  <a href="https://github.com/TrustworthyComputing/mastic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</h1>

## Building

Please note that this repository relies on `x86_64` specific instructions in [prg.rs](src/prg.rs).
First, make sure that you have a working Rust installation:
```bash
❯❯ rustc --version
rustc 1.74.0
❯❯ cargo --version
cargo 1.74.0
```

Next, build from sources using:
```bash
❯❯ cargo build --release
```

## Running

#### Server 0:
```bash
cargo run --release --bin server -- --config src/configs/config.toml --server_id 0
```

#### Server 1:
```bash
cargo run --release --bin server -- --config src/configs/config.toml --server_id 1
```
Now, the servers should be ready to process client requests.

#### Clients:
In another shell, run the following command to send 100 client requests to the servers.
```bash
cargo run --release --bin driver -- --config src/configs/config.toml -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/configs/config.toml -n 100 --malicious 0.05
```


#### The config file
The client and servers use a common configuration file, which contains the parameters for the
system. An example of one such file is in `src/configs/config.toml`. The contents of that file are here:

```toml
data_bits = 8                      # Number of bytes of each string.
range_bits = 2                      # Number of bits for the range check.

threshold = 0.01                    # Threshold for weighted heavy hitters.

server_0 = "0.0.0.0:8000"           # The `IP:port` for server 0.
server_1 = "0.0.0.0:8001"           # The `IP:port` for server 1.

add_report_share_batch_size = 1000  # Size of RPC requests for transmitting keys.
query_flp_batch_size = 100000       # Size of RPC requests for transmitting FLPs.

zipf_unique_buckets = 1000          # Zipf parameter
zipf_exponent = 1.03                # Zipf exponent
```

## Disclaimer

This is software for a research prototype and not production-ready code. This repository builds upon
[plasma](https://github.com/TrustworthyComputing/plasma),
[heavy-hitters](https://github.com/henrycg/heavyhitters), and
[libprio-rs](https://github.com/divviup/libprio-rs/tree/main).

This is a Rust implementation of the ideas presented in Mastic Verifiable
Distributed Aggregation Function (VDAF) individual Internet-Draft. You can read
the draft on the [Datatracker Page](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/).
