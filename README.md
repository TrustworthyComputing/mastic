<h1 align="center">Mastic: Private Aggregated Statistics through Fully Linear Proofs
  <a href="https://github.com/jimouris/mastic/actions/workflows/ci-build.yml"><img src="https://github.com/jimouris/mastic/workflows/ci-build/badge.svg"></a>
  <a href="https://github.com/jimouris/mastic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</h1>


This is a Rust implementation of the ideas presented in the Mastic Verifiable Distributed
Aggregation Function (VDAF) individual Internet-Draft. You can read the draft on the [Datatracker
Page](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/).


## Building

Please note that this repository relies on `x86_64` specific instructions in [prg.rs](src/prg.rs).
First, make sure that you have a working Rust installation:
```bash
❯❯ rustc --version
rustc 1.73.0
❯❯ cargo --version
cargo 1.73.0
```

Next, build from sources using:
```bash
❯❯ cargo build --release
```

## Running

#### Server 0:
```bash
cargo run --release --bin server -- --config src/bin/config.json --server_id 0
```

#### Server 1:
```bash
cargo run --release --bin server -- --config src/bin/config.json --server_id 1
```
Now, the servers should be ready to process client requests.

#### Clients:
In another shell, run the following command to send 100 client requests to the servers.
```bash
cargo run --release --bin driver -- --config src/bin/config.json -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the
percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious
clients use:
```bash
cargo run --release --bin driver -- --config src/bin/config.json -n 100 --malicious 0.05
```


#### The config file
The client and servers use a common configuration file, which contains the parameters for the
system. An example of one such file is in `src/bin/config.json`. The contents of that file are here:

```bash
{
  "data_bytes": 4,
  "threshold": 0.01,
  "server_0": "0.0.0.0:8000",
  "server_1": "0.0.0.0:8001",
  "add_key_batch_size": 1000,
  "flp_batch_size": 100000,
  "unique_buckets": 1000,
  "zipf_exponent": 1.03
}
```

The parameters are:
* `data_bytes`: Number of bytes of each string (x8 for bits).
* `threshold`: The servers will output the collection of strings that more than a `threshold` of
  clients hold.
* `server0`, `server1`, and `server2`: The `IP:port` of tuple for the two servers. The servers can
  run on different IP addresses, but these IPs must be publicly addressable.
* `add_key_batch_size`: The number of each type of RPC request to bundle together. The underlying RPC
  library has an annoying limit on the size of each RPC request, so you cannot set these values too
  large.
* `flp_batch_size`: Similar to `add_key_batch_size` but with a greater threshold.
* `unique_buckets` and `zipf_exponent`: Each simulated client samples its private string from a Zipf
  distribution over strings with parameter `zipf_exponent` and support `unique_buckets`.


## Disclaimer

This is software for a research prototype and not production-ready code. This repository builds upon
[plasma](https://github.com/TrustworthyComputing/plasma),
[heavy-hitters](https://github.com/henrycg/heavyhitters), and
[libprio-rs](https://github.com/divviup/libprio-rs/tree/main).


<p align="center">
  <img src="./logos/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>
