# Artifact Appendix

Paper title: **Mastic: Private Weighted Heavy-Hitters and Attribute-Based Metrics**

Artifacts HotCRP Id: **#4** (not your paper Id, but the artifacts id)

Requested Badge: **Reproduced**

## Description
Private heavy-hitters is a data-collection task where multiple clients possess
private bit strings, and data-collection servers aim to identify the most
popular strings without learning anything about the clients' inputs. In this
work, we introduce Mastic: a private analytics framework in the two-server
setting that protects the privacy of honest clients and the correctness of the
protocol against malicious clients. Mastic supports two modes of operation,
namely weighted heavy hitters and attribute based metrics.


The artifact consists of two binaries:
1. `server`: We run this three times with different ids.
2. `driver`: The driver is used to emulate multiple clients and connect to the
   three servers.

https://github.com/TrustworthyComputing/mastic

### Security/Privacy Issues and Ethical Concerns (All badges)
N/A (i.e., no concerns or risk)

## Basic Requirements (Only for Functional and Reproduced badges)
The repository has been tested with both Ubuntu and a Mac laptops as well as
with AWS servers. It does not have any special requirements and most common
computers will be able to run this artifact.

### Hardware Requirements
N/A

### Software Requirements
We tested on Ubuntu and have also tested on an M2 Mac. The only requirement is
Rust and `build-essential` (for Ubuntu).

We also provide a Dockerfile for easier use.

### Estimated Time and Storage Consumption
Building with Docker might take up to a minute while building from scratch is
faster. The artifact does not have any special storage requirements.
The runtime highly depends on the provided inputs. Running with docker spawns
1000 clients and finishes in under a second (Ctrl+C at the end to exit the
docker compose).

## Environment
Our artifact is public at *https://github.com/TrustworthyComputing/mastic*.


### Accessibility (All badges)
https://github.com/TrustworthyComputing/mastic commit id 86b3cbd.


### Set up the environment (Only for Functional and Reproduced badges)
#### Option 1: PETS VM
We have setup Mastic in the following VM:
```bash
To connect use "ssh artifacts@pets-x7e9-1-165-docker.artifacts.measurement.network"

Hostname:	pets-x7e9-1-165-docker.artifacts.measurement.network
Username:	artifacts
Password:	<INCLUDED WITH SUBMISSION>
```
You can either run it using Docker or directly using cargo. (see running section)

#### Option 2: Docker
First clone the repository:
```bash
git clone https://github.com/TrustworthyComputing/mastic.git
```
and then run:
```bash
CONFIG=weighted-heavy-hitters.toml docker compose up
```
This will build the server and the driver, it will spawn two servers, and
finally a driver that will connect to the two servers and run our weighted
heavy hitters protocol. Once it's done, press `^C` to stop the two servers.

Similarly, for the two other modes that Mastic supports:
```bash
CONFIG=attribute-based-metrics.toml docker compose up
```
and
```bash
CONFIG=plain-metrics.toml docker compose up
```

#### Option 3: Build from sources
You can also run Mastic directly from your machine.
Install dependencies:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sudo apt install build-essential
```
Clone and build:
```bash
git clone https://github.com/TrustworthyComputing/mastic.git
cd mastic
cargo build -r
```

Run the two servers in the background:
```bash
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 0 &
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 1 &
```
And finally run the driver:
```bash
cargo run --release --bin driver -- --config src/configs/weighted-heavy-hitters.toml -n 100
```
Don't forget to kill the servers (`fg` and then `^C` two times).


Similarly, you can run our other modes as:
```bash
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 0 &
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 1 &
```
and
```bash
cargo run --release --bin driver -- --config src/configs/attribute-based-metrics.toml -n 100
```

and lastly:
```bash
cargo run --release --bin server -- --config src/configs/plain-metrics.toml --server_id 0 &
cargo run --release --bin server -- --config src/configs/plain-metrics.toml --server_id 1 &
```
and
```bash
cargo run --release --bin driver -- --config src/configs/plain-metrics.toml -n 100
```

All the driver binaries can get a `--malicious` flag for malicious clients. Use it as:
```bash
cargo run --release --bin driver -- --config src/configs/plain-metrics.toml -n 100 --malicious 0.05
```
for 5% malicious.



## Artifact Evaluation (Only for Functional and Reproduced badges)

### Main Results and Claims
New protocol for weighted heavy-hitters and attribute based metrics. Our protocol also supports malicious clients.

#### Main Result 1: Weighted Heavy Hitters
Run the two servers in the background:
```bash
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 0 &
cargo run --release --bin server -- --config src/configs/weighted-heavy-hitters.toml --server_id 1 &
```
And finally run the driver:
```bash
cargo run --release --bin driver -- --config src/configs/weighted-heavy-hitters.toml -n 100
```

You'll see something like:
```bash
Running with 0% malicious clients
- Mode: WeightedHeavyHitters { threshold: 0.01 }
- Using 4 histogram buckets
- Using Some(8) bits
Generating reports...
	- Nonce size: 16 bytes
	- JR size: 16 bytes
	- VIDPFKey size: 1329 bytes
	- FLP proof size: 272 bytes
Generated 1000 keys in 0.010254411 seconds (1.0254411e-5 sec/key)
tree_init: 1.6413e-5
tree_init: 1.6708e-5
...
Tree crawl last: 0.002939035 sec.
Tree crawl last: 0.003250196 sec.
- Time for level 8: 0.004291782

Value (00011010) 	 Count: [0, 0, 0, 1, 1]
Value (00100100) 	 Count: [0, 0, 0, 1, 1]
Value (00111010) 	 Count: [2, 0, 0, 1, 3]
Value (00111110) 	 Count: [0, 0, 0, 1, 1]
Value (01001011) 	 Count: [0, 0, 0, 1, 1]
Value (01001110) 	 Count: [0, 0, 0, 1, 1]
Value (01101011) 	 Count: [1, 0, 1, 2, 4]
Value (01110100) 	 Count: [0, 0, 0, 1, 1]
Value (01111001) 	 Count: [0, 1, 0, 10, 11]
Value (10011001) 	 Count: [0, 0, 0, 1, 1]
Value (10011100) 	 Count: [0, 0, 0, 1, 1]
Value (10100111) 	 Count: [0, 0, 0, 2, 2]
Value (10110100) 	 Count: [0, 0, 0, 1, 1]
Value (11101010) 	 Count: [0, 0, 0, 1, 1]
Value (11101011) 	 Count: [0, 0, 0, 1, 1]
Value (11101100) 	 Count: [1, 0, 0, 1, 2]
Value (11111101) 	 Count: [1, 0, 0, 1, 2]
Total time 0.025981784
```

For each string e.g., `11111101` we get a histogram e.g., `[1, 0, 0, 1, 2]` with
`- Using 4 histogram buckets` which means that it has four buckets for the
measurement + 1 for the total count. So `[1, 0, 0, 1, 2]` means 1 vote for the
first, 1 vote for the fourth, and total 2 votes.


#### Main Result 2: Attribute Based Metrics
Run the two servers in the background:
```bash
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 0 &
cargo run --release --bin server -- --config src/configs/attribute-based-metrics.toml --server_id 1 &
```
And finally run the driver:
```bash
cargo run --release --bin driver -- --config src/configs/attribute-based-metrics.toml -n 100
```

You'll see something like:
```bash
Running with 0% malicious clients
- Mode: AttributeBasedMetrics { num_attributes: 10 }
- Using 4 histogram buckets
- Using Some(8) bits
Generating reports...
	- Nonce size: 16 bytes
	- JR size: 16 bytes
	- VIDPFKey size: 1329 bytes
	- FLP proof size: 272 bytes
Generated 1000 keys in 0.00812144 seconds (8.121440000000001e-6 sec/key)
Using 8 attributes
0..100: report validation completed in 9.154494ms: rejected 0 reports
0..100: report aggregation completed in 262.654µs
10001100: [3, 0, 0, 0]
01110111: [0, 2, 0, 0]
01010000: [0, 1, 0, 0]
11001010: [0, 0, 0, 0]
11101011: [0, 1, 0, 0]
10011010: [0, 0, 1, 0]
10100111: [7, 0, 0, 0]
01000100: [1, 0, 0, 0]
Total time 0.009484934
```

In this case as we don't do heavy hitters, you see as many buckets in the
histogram as in the print message: `4 histogram buckets`. Each string e.g.,
`11101011` represents an attribute.

Lastly, you can run both weighted heavy hitters and attribute based metrics with malicious clients by passing the `--malicious` and a percentage.


# Experiments

## Understanding the configuration files
Our experiments can be reproduced by using our config files: https://github.com/TrustworthyComputing/mastic/tree/main/src/configs and the values provided in the paper.

For instance:
1) weighted_heavy_hitters 64-bit inputs:
```toml
mode.weighted_heavy_hitters.threshold = 0.01

data_bits = 64
hist_buckets = 4

server_0 = "0.0.0.0:8000"
server_1 = "0.0.0.0:8001"

add_report_share_batch_size = 1000
query_flp_batch_size = 1000
zipf_unique_buckets = 100
zipf_exponent = 1.03
```

2) NEL 256-bit inputs with 10 buckets:
```toml
mode.weighted_heavy_hitters.threshold = 0.01

data_bits = 256
hist_buckets = 10

server_0 = "0.0.0.0:8000"
server_1 = "0.0.0.0:8001"

add_report_share_batch_size = 500
query_flp_batch_size = 100000
zipf_unique_buckets = 1000
zipf_exponent = 1.03
```

3) Attribute based metrics application with 10 buckets:
```toml
mode.attribute_based_metrics.num_attributes = 10

data_bits = 32
hist_buckets = 10

server_0 = "0.0.0.0:8000"
server_1 = "0.0.0.0:8001"

add_report_share_batch_size = 1000
query_flp_batch_size = 100000
zipf_unique_buckets = 1000
zipf_exponent = 1.03
```
etc. These parameters are sufficient to reproduce all our results -- all our
experiments in the paper specify the parameters used.

## Reproducing Experiments and Figures
To reproduce our experiments, use the configs from the [configs](./configs/)
directory and the scripts from the [plots](../plots/) directory.

## Troubleshooting
As mentioned in the **Troubleshooting** section of the [README file](../README.md) file,
Mastic relies on the [tarpc](https://github.com/google/tarpc) library which has
a limit on the size of the RPC messages. As such, you might see an error similar
to the following:
```shell
thread 'main' panicked at src/bin/driver.rs:335:
called `Result::unwrap()` on an `Err` value: Disconnected
```
which is caused by the RPC batch sizes.

In case you run into this issue, you can fix this easily by reducing the batch
sizes of either the reports or the FLPs (or both).
```toml
add_report_share_batch_size = 1000
query_flp_batch_size = 100000
```
**Note:** this does not affect the online running time, but it affects the
upload time from the `driver` to the Mastic servers. In other words, this does
not change the experiments but will make setting up the experiments faster. For
this reason, most of the provided configs use the default batch sizes, which may
cause crashes with more clients or bits, but this can be simply resolved by
reducing the batch sizes.
