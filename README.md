# PLASMA: Private, Lightweight Aggregated Statistics against Malicious Adversaries with Full Security
### WARNING: This is not production-ready code.

This is software for a research prototype. Please
do *NOT* use this code in production.
This repository builds upon [heavy-hitters](https://github.com/henrycg/heavyhitters).


## Getting started
First, make sure that you have a working Rust installation:

```bash
$ rustc --version   
rustc 1.65.0-nightly
$ cargo --version
cargo 1.65.0-nightly
```

### Build from sources
```bash
cargo build --release
```

## Heavy Hitters

Server 0:
```bash
$ cargo run --release --bin hh-server -- --config src/bin/config_32.json --server_id 0
```

Server 1:
```bash
$ cargo run --release --bin hh-server -- --config src/bin/config_32.json --server_id 1
```

Server 2:
```bash
$ cargo run --release --bin hh-server -- --config src/bin/config_32.json --server_id 2
```

Now, the servers should be ready to process client requests. In a third shell, run the following command to send 100 client requests to the servers (this will take some time):

Clients:
```bash
$ cargo run --release --bin hh-leader -- --config src/bin/config_32.json -n 100
```

## Histogram

Server 0:
```bash
$ cargo run --release --bin histogram-server -- --config src/bin/config_8_histogram.json --server_id 0
```

Server 1:
```bash
$ cargo run --release --bin histogram-server -- --config src/bin/config_8_histogram.json --server_id 1
```

Server 2:
```bash
$ cargo run --release --bin histogram-server -- --config src/bin/config_8_histogram.json --server_id 2
```

Now, the servers should be ready to process client requests. In a third shell, run the following command to send 100 client requests to the servers (this will take some time):

Clients:
```bash
$ cargo run --release --bin histogram-leader -- --config src/bin/config_8_histogram.json -n 100
```


## The config file

The client and servers use a common configuration file, which contains the parameters for the system. An example of one such file is in `src/bin/config_32.json`. The contents of that file are here:

```
{
  "data_bytes": 4,
  "threshold": 0.01,
  "server_0": "0.0.0.0:8000",
  "server_1": "0.0.0.0:8001",
  "server_2": "0.0.0.0:8002",
  "addkey_batch_size": 100,
  "unique_buckets": 10,
  "zipf_exponent": 1.03
}
```

The parameters are:

* `data_bytes`: The bitlength of each client's private string. In iDPF this is #bits, in Histograms this is #bytes
* `threshold`: The servers will output the collection of strings that more than a `threshold` of clients hold.
* `server0` and `server1`: The `IP:port` of tuple for the two servers. The servers can run on different IP addresses, but these IPs must be publicly addressable.
* `*_batch_size`: The number of each type of RPC request to bundle together. The underlying RPC library has an annoying limit on the size of each RPC request, so you cannot set these values too large.
* `unique_buckets` and `zipf_exponent`: Each simulated client samples its private string from a Zipf distribution over strings with parameter `zipf_exponent` and support `unique_buckets`.
