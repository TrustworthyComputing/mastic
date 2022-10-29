# Incremental Distributed Point Functions for Plus Codes
## WARNING: This is not production-ready code.

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

### Run tets
```bash
$ cargo test
... lots of output ...
```

## iDPF with Malicious sketching checkout to branch "sketches"
## iDPF without Malicious sketching

Server 0:
```bash
$ cargo run --release --bin idpf-server -- --config src/bin/config.json --server_id 0
```

Server 1:
```bash
$ cargo run --release --bin idpf-server -- --config src/bin/config.json --server_id 1
```

Now, the servers should be ready to process client requests. In a third shell, run the following command to send 100 client requests to the servers (this will take some time):

Clients:
```bash
$ cargo run --release --bin idpf-leader -- --config src/bin/config.json -n 100
```

## Histogram

Server 0:
```bash
$ cargo run --release --bin histogram-server -- --config src/bin/histogram.json --server_id 0
```

Server 1:
```bash
$ cargo run --release --bin histogram-server -- --config src/bin/histogram.json --server_id 1
```

Now, the servers should be ready to process client requests. In a third shell, run the following command to send 100 client requests to the servers (this will take some time):

Clients:
```bash
$ cargo run --release --bin histogram-leader -- --config src/bin/histogram.json -n 100
```


## The config file

The client and servers use a common configuration file, which contains the parameters for the system. An example of one such file is in `src/bin/config.json`. The contents of that file are here:

```
{
  "data_len": 512, // in iDPF this is #bits, in Histograms this is #bytes
  "threshold": 0.001,
  "server0": "0.0.0.0:8000",
  "server1": "0.0.0.0:8001",
  "addkey_batch_size": 100,
  "sketch_batch_size": 100000,
  "sketch_batch_size_last": 25000,
  "unique_buckets": 10000,
  "zipf_exponent": 1.03
}
```

The parameters are:

* `data_len`: The bitlength of each client's private string. In iDPF this is #bits, in Histograms this is #bytes
* `threshold`: The servers will output the collection of strings that more than a `threshold` of clients hold.
* `server0` and `server1`: The `IP:port` of tuple for the two servers. The servers can run on different IP addresses, but these IPs must be publicly addressable.
* `*_batch_size`: The number of each type of RPC request to bundle together. The underlying RPC library has an annoying limit on the size of each RPC request, so you cannot set these values too large.
* `unique_buckets` and `zipf_exponent`: Each simulated client samples its private string from a Zipf distribution over strings with parameter `zipf_exponent` and support `unique_buckets`.


Local testing:
```bash
$ cargo run --release --bin idpf-main -- --config src/bin/test.json
$ cargo run --release --bin histogram-main -- --config src/bin/histogram.json -n 100
```