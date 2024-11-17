<h1 align="center">Mastic: Private Weighted Heavy-Hitters and Attribute-Based Metrics
  <a href="https://github.com/TrustworthyComputing/mastic/actions/workflows/ci-build.yml"><img src="https://github.com/TrustworthyComputing/mastic/workflows/ci-build/badge.svg"></a>
  <a href="https://github.com/TrustworthyComputing/mastic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</h1>

## How to cite this work
Mastic appears in [Proceedings on Privacy Enhancing Technologies (PoPETS), 2025](https://petsymposium.org/popets/2025/popets-2025-0017.php).
The preprint can be accessed [here](https://eprint.iacr.org/2024/221); you can
cite this work as follows:
```bibtex
@Article{PoPETS:MPDST25,
  author    =   "Dimitris Mouris and
                 Christopher Patton and
                 Hannah Davis and
                 Pratik Sarkar and
                 Nektarios Georgios Tsoutsos",
  title     =   "{Mastic: Private Weighted Heavy-Hitters and Attribute-Based Metrics}",
  year      =   2025,
  volume    =   2025,
  month     =   July,
  journal   =   "{Proceedings on Privacy Enhancing Technologies}",
  number    =   1,
  pages     =   "290--319",
  doi       =   "10.56553/popets-2025-0017"
}
```

## Build & Run With Docker Compose
The following runs two aggregators and the leader each in a different container
for weighted heavy hitters:
```bash
❯❯ CONFIG=weighted-heavy-hitters.toml docker compose up
```
Similarly, for the two other modes that Mastic supports:
```bash
❯❯ CONFIG=attribute-based-metrics.toml docker compose up
❯❯ CONFIG=plain-metrics.toml docker compose up
```

## Building

First, make sure that you have a working [Rust installation](https://www.rust-lang.org/tools/install):
```bash
❯❯ rustc --version
rustc 1.82.0
❯❯ cargo --version
cargo 1.82.0
```

Next, build from sources using:
```bash
❯❯ cargo build --release

...
Finished `release` profile [optimized] target(s) in ...s
```

## Running

### The config file
The client and servers use a common configuration file, which contains the
parameters for the system. The config file is also used to choose between the
different modes of operation. Here, we show the basic structure of the config
file. Each mode (Weighted Heavy Hitters, Attribute-Based Metrics, and Plain
Metrics with Prio) uses a different config. The contents that are shared between
all the config files are shown below:

```toml
data_bits = 8                       # Number of bits of each string.
hist_buckets = 2                    # Number of each histogram buckets

# [mode]                            # Mode of operation, one of:
# mode.weighted_heavy_hitters.threshold = 0.01
# mode.attribute_based_metrics.num_attributes = 10
# mode = "plain_metrics"

server_0 = "0.0.0.0:8000"           # The `IP:port` for server 0.
server_1 = "0.0.0.0:8001"           # The `IP:port` for server 1.

add_report_share_batch_size = 1000  # Size of RPC requests for transmitting keys.
query_flp_batch_size = 100000       # Size of RPC requests for transmitting FLPs.

zipf_unique_buckets = 1000          # Zipf parameter
zipf_exponent = 1.03                # Zipf exponent
```

### 1. Weighted Heavy Hitters
[weighted-heavy-hitters.toml](./src/configs/weighted-heavy-hitters.toml)
```toml
# ...
mode.weighted_heavy_hitters.threshold = 0.01
# ...
```

#### Weighted Heavy Hitters: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 0
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 1
```

#### Weighted Heavy Hitters: Clients
In another shell, send 100 client requests to the Aggregators:
```bash
cargo run --release --bin driver -- --config src/configs/weighted-heavy-hitters.toml -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/configs/weighted-heavy-hitters.toml -n 100 --malicious 0.05
```

### 2. Attribute-Based Metrics
[attribute-based-metrics.toml](./src/configs/attribute-based-metrics.toml)
```toml
# ...
mode.attribute_based_metrics.num_attributes = 10
# ...
```

#### Attribute-Based Metrics: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 0
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 1
```

#### Attribute-Based Metrics: Clients
In another shell, send 100 client requests to the Aggregators:
```bash
cargo run --release --bin driver -- --config src/configs/attribute-based-metrics.toml -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/configs/attribute-based-metrics.toml -n 100 --malicious 0.05
```

### 3. Plain Metrics with Prio
[plain-metrics.toml](./src/configs/plain-metrics.toml)
```toml
# ...
mode = "plain_metrics"
# ...
```

#### Plain Metrics with Prio: Aggregators
Run the aggregators in two separate shells. They will wait and be ready to
process client requests.
```bash
cargo run --release --bin server -- --config src/configs/plain-metrics.toml --server_id 0
cargo run --release --bin server -- --config src/configs/plain-metrics.toml --server_id 1
```

#### Plain Metrics with Prio: Clients
In another shell, send 100 client requests to the servers:
```bash
cargo run --release --bin driver -- --config src/configs/plain-metrics.toml -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/configs/plain-metrics.toml -n 100 --malicious 0.05
```

### 4. Plain Heavy Hitters with Mastic
This branch can do Plain Heavy Hitters by setting the histogram size to 1, but a
more efficient implementation uses the `Count` circuit and is in the [`Count`
branch](https://github.com/TrustworthyComputing/mastic/tree/Count).

## Troubleshooting
Mastic relies on the [tarpc](https://github.com/google/tarpc) library which has
a limit on the size of the RPC messages. As such, you might see an error similar
to the following:
```shell
thread 'main' panicked at src/bin/driver.rs:335:
called `Result::unwrap()` on an `Err` value: Disconnected
```
which is caused by the RPC batch sizes.

To fix this, reduce the batch sizes of either the reports or the FLPs (or both).
```toml
add_report_share_batch_size = 1000
query_flp_batch_size = 100000
```
**Note:** this does not affect the online running time, but it affects the
upload time from the `driver` to the Mastic servers.

## Disclaimer

This is software for a research prototype and not production-ready code. This repository builds upon
[plasma](https://github.com/TrustworthyComputing/plasma),
[heavy-hitters](https://github.com/henrycg/heavyhitters), and
[libprio-rs](https://github.com/divviup/libprio-rs/tree/main).

This is a Rust implementation of the ideas presented in Mastic Verifiable
Distributed Aggregation Function (VDAF) individual Internet-Draft. You can read
the draft on the [Datatracker Page](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/).

## Acknowledgments
This work was partially supported by the National Science Foundation (Award #2239334).
