use std::{fs, net::SocketAddr};

use clap::{App, Arg};
use serde::Deserialize;

/// Parameters used by the driver program to generate test data.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Simulate weighted heavy hitters. In this mode, the aggregators compute the subset of inputs
    /// whose total weight exceed a given threshold.
    WeightedHeavyHitters {
        /// The weighted heavy hitters threshold.
        threshold: f64,
    },

    /// Simulate attribute-based metrics. In this mode, the aggregators agree on a set of
    /// attributes to use to partition the metrics.
    AttributeBasedMetrics {
        /// For testing purposes, the driver will sample `num_attributes` inputs from the same
        /// distribution as the clients.
        num_attributes: usize,
    },

    /// Simulate plain metrics, aggregated using Prio3 instead of Mastic.
    PlainMetrics,
}

#[derive(Deserialize)]
pub struct Config {
    /// Number of bits of each string.
    pub data_bits: Option<usize>,

    /// Number of histogram buckets for the FLP range check.
    pub hist_buckets: usize,

    /// The servers will output the collection of strings that more than a `threshold` of clients
    /// hold.
    pub add_key_batch_size: usize,

    /// Similar to `add_key_batch_size` but with a greater threshold.
    pub flp_batch_size: usize,

    /// Zipf parameter: Number of distinct strings.
    pub unique_buckets: usize,

    /// Mode of operation in which to test Mastic.
    pub mode: Mode,

    /// Zipf parameter: The distribution from which each client chooses its input.
    pub zipf_exponent: f64,

    /// The `IP:port` tuple for server 0.
    pub server_0: SocketAddr,

    /// The `IP:port` tuple for server 1.
    pub server_1: SocketAddr,
}

pub fn get_config(filename: &str) -> Config {
    let toml_data = &fs::read_to_string(filename).expect("Cannot open TOML file");
    toml::from_str(toml_data).expect("Cannot parse TOML config")
}

pub fn get_args(
    name: &str,
    get_server_id: bool,
    get_n_reqs: bool,
    get_malicious: bool,
) -> (Config, i8, usize, f32) {
    let mut flags = App::new(name)
        .version("0.1")
        .about("Mastic: Private Aggregated Statistics through Fully Linear Proofs")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILENAME")
                .help("Location of JSON config file")
                .required(true)
                .takes_value(true),
        );
    if get_server_id {
        flags = flags.arg(
            Arg::with_name("server_id")
                .short("i")
                .long("server_id")
                .value_name("NUMBER")
                .help("Zero-indexed ID of server")
                .required(true)
                .takes_value(true),
        );
    }
    if get_n_reqs {
        flags = flags.arg(
            Arg::with_name("num_clients")
                .short("n")
                .long("num_clients")
                .value_name("NUMBER")
                .help("Number of client requests to generate")
                .required(true)
                .takes_value(true),
        );
    }
    if get_malicious {
        flags = flags.arg(
            Arg::with_name("malicious")
                .short("m")
                .long("malicious")
                .value_name("NUMBER")
                .help("Percentage of malicious clients")
                .required(false)
                .takes_value(true),
        );
    }

    let flags = flags.get_matches();

    let mut server_id = -1;
    if get_server_id {
        server_id = flags.value_of("server_id").unwrap().parse().unwrap();
    }

    let mut n_reqs = 0;
    if get_n_reqs {
        n_reqs = flags.value_of("num_clients").unwrap().parse().unwrap();
    }

    let mut malicious = 0.0;
    if flags.is_present("malicious") {
        malicious = flags.value_of("malicious").unwrap().parse::<f32>().unwrap();
    }

    (
        get_config(flags.value_of("config").unwrap()),
        server_id,
        n_reqs,
        malicious,
    )
}
