<h1 align="center">Mastic: Private Weighted Heavy-Hitters and Attribute-Based Metrics
  <a href="https://github.com/jimouris/mastic/actions/workflows/ci-build.yml"><img src="https://github.com/jimouris/mastic/workflows/ci-build/badge.svg"></a>
  <a href="https://github.com/jimouris/mastic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</h1>

## Building

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

### The config file
The client and servers use a common configuration file, which contains the
parameters for the system. The config file is also used to choose between the
different modes of operation. Here, we show the basic structure of the config
file. Each mode (Weighted Heavy Hitters, Attribute-Based Metrics, and Plain
Metrics with Prio) uses a different config. The contents that are shared between
all the config files are shown below:

```bash
{
  "data_bytes": 1,            # Number of bytes of each string (x8 for bits).
  "hist_buckets": 2,          # Number of each histogram buckets
  "mode": ...,                # See below.
  "server_0": "0.0.0.0:8000", # The `IP:port` for server 0.
  "server_1": "0.0.0.0:8001", # The `IP:port` for server 1.
  "add_key_batch_size": 1000, # Size of RPC requests for transmitting keys.
  "flp_batch_size": 100000,   # Size of RPC requests for transmitting FLPs.
  "unique_buckets": 1000,     # Zipf parameter
  "zipf_exponent": 1.03       # Zipf exponent
}
```

### 1. Weighted Heavy Hitters
[Config-weights.json](./src/bin/config-weights.json)
```bash
  ...
  "mode": {
    "weighted_heavy_hitters": {
      "threshold": 0.01
    }
  },
  ...
```

#### Weighted Heavy Hitters: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/bin/config-weights.json --server_id 0
cargo run --release --bin server -- --config src/bin/config-weights.json --server_id 1
```

#### Weighted Heavy Hitters: Clients
In another shell, send 100 client requests to the Aggregators:
```bash
cargo run --release --bin driver -- --config src/bin/config-weights.json -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/bin/config-weights.json -n 100 --malicious 0.05
```

### 2. Attribute-Based Metrics
[Config-attributes.json](./src/bin/config-attributes.json)
```bash
  ...
  "mode": {
    "attribute_based_metrics": {
      "threshold": 10
    }
  },
  ...
```

#### Attribute-Based Metrics: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/bin/config-attributes.json --server_id 0
cargo run --release --bin server -- --config src/bin/config-attributes.json --server_id 1
```

#### Attribute-Based Metrics: Clients
In another shell, send 100 client requests to the Aggregators:
```bash
cargo run --release --bin driver -- --config src/bin/config-attributes.json -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/bin/config-attributes.json -n 100 --malicious 0.05
```

### 3. Plain Metrics with Prio
[Config-plain.json](./src/bin/config-plain.json)
```bash
  ...
  "data_bytes": 0, # This is unused in this use-case
  "mode": "plain_metrics",
  ...
```

#### Plain Metrics with Prios: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/bin/config-plain.json --server_id 0
cargo run --release --bin server -- --config src/bin/config-plain.json --server_id 1
```

#### Plain Metrics with Prio: Clients
In another shell, send 100 client requests to the servers:
```bash
cargo run --release --bin driver -- --config src/bin/config-plain.json -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/bin/config-plain.json -n 100 --malicious 0.05
```


## Disclaimer

This is software for a research prototype and not production-ready code. This repository builds upon
[plasma](https://github.com/TrustworthyComputing/plasma),
[heavy-hitters](https://github.com/henrycg/heavyhitters), and
[libprio-rs](https://github.com/divviup/libprio-rs/tree/main).

This is a Rust implementation of the ideas presented in Mastic Verifiable
Distributed Aggregation Function (VDAF) individual Internet-Draft. You can read
the draft on the [Datatracker Page](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/).

<p align="center">
  <img src="./logos/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>
