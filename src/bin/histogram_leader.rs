use dpf_codes::{
    FieldElm,
    collect,
    config,
    dpf,
    fastfield,
    histogram_rpc::{
        HistogramAddKeysRequest,
        HistogramResetRequest, 
        HistogramTreeInitRequest,
        HistogramTreeCrawlRequest, 
        HistogramTreeCrawlLastRequest, 
        HistogramAddLeavesBetweenClientsRequest
    },
};

use futures::try_join;
use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use rand::{Rng, distributions::Alphanumeric,};
use rayon::prelude::*;
use std::{io, time::{Duration, SystemTime, Instant},};
use tarpc::{client, context, tokio_serde::formats::Json,};

type Key = dpf::DPFKey<fastfield::FE,FieldElm>;

fn long_context() -> context::Context {
    let mut ctx = context::current();

    // Increase timeout to one hour
    ctx.deadline = SystemTime::now() + Duration::from_secs(1000000);
    ctx
}


fn sample_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len / 8)
        .collect()
}

fn generate_keys(cfg: &config::Config) -> (Vec<Key>, Vec<Key>) {
    println!("data_len = {}\n", cfg.data_len);

    let (keys0, keys1): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .enumerate()
        .map(|(i, _)| {
            let data_string = sample_string(cfg.data_len * 8);
            let bit_str = dpf_codes::bits_to_bitstring(
                dpf_codes::string_to_bits(&data_string).as_slice()
            );
            println!("Client({}) \t input \"{}\" ({})", i, data_string, bit_str);
            
            dpf::DPFKey::gen_from_str(&data_string)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys0[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    (keys0, keys1)
}

async fn reset_servers(
    client0: &mut dpf_codes::HistogramCollectorClient,
    client1: &mut dpf_codes::HistogramCollectorClient,
) -> io::Result<()> {
    let req = HistogramResetRequest {};
    let response0 = client0.reset(long_context(), req.clone());
    let response1 = client1.reset(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn tree_init(
    client0: &mut dpf_codes::HistogramCollectorClient,
    client1: &mut dpf_codes::HistogramCollectorClient,
) -> io::Result<()> {
    let req = HistogramTreeInitRequest {};
    let response0 = client0.tree_init(long_context(), req.clone());
    let response1 = client1.tree_init(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    client0: dpf_codes::HistogramCollectorClient,
    client1: dpf_codes::HistogramCollectorClient,
    keys0: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    keys1: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    nreqs: usize,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkey0 = Vec::with_capacity(nreqs);
    let mut addkey1 = Vec::with_capacity(nreqs);

    for _ in 0..nreqs {
        let idx = zipf.sample(&mut rng) - 1;
        addkey0.push(keys0[idx].clone());
        addkey1.push(keys1[idx].clone());
    }

    let req0 = HistogramAddKeysRequest { keys: addkey0 };
    let req1 = HistogramAddKeysRequest { keys: addkey1 };

    let response0 = client0.add_keys(long_context(), req0.clone());
    let response1 = client1.add_keys(long_context(), req1.clone());

    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn run_level(
    client0: &mut dpf_codes::HistogramCollectorClient,
    client1: &mut dpf_codes::HistogramCollectorClient,
    level: usize,
    start_time: Instant,
) -> io::Result<usize> {
    // Tree crawl
    println!(
        "TreeCrawlStart {:?} {:?} {:?}",
        level,
        "-",
        start_time.elapsed().as_secs_f64()
    );
    let req = HistogramTreeCrawlRequest {};
    let response0 = client0.histogram_tree_crawl(long_context(), req.clone());
    let response1 = client1.histogram_tree_crawl(long_context(), req);
    let (vals0, vals1) = try_join!(response0, response1).unwrap();
    println!(
        "TreeCrawlDone {:?} {:?} {:?}",
        level,
        "-",
        start_time.elapsed().as_secs_f64()
    );

    assert_eq!(vals0.len(), vals1.len());
    Ok(vals0.len())
}

async fn run_level_last(
    client0: &mut dpf_codes::HistogramCollectorClient,
    client1: &mut dpf_codes::HistogramCollectorClient,
    start_time: Instant,
) -> io::Result<usize> {
    // Tree crawl
    println!(
        "TreeCrawlStart last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );
    let req = HistogramTreeCrawlLastRequest {};
    let response0 = client0.histogram_tree_crawl_last(long_context(), req.clone());
    let response1 = client1.histogram_tree_crawl_last(long_context(), req);
    let ((hashes0, tau_vals0), (hashes1, tau_vals1)) = try_join!(response0, response1).unwrap();
    println!(
        "TreeCrawlDone last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );

    assert_eq!(hashes0.len(), hashes1.len());
    let mut verified = vec![true; hashes0.len()];

    let tau_vals = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals0, &tau_vals1
    );

    for ((i, h0), h1) in hashes0.iter().enumerate().zip_eq(hashes1) {
        let matching = h0.iter().zip(h1.iter()).filter(|&(h0, h1)| h0 == h1).count();
        if h0.len() != matching || tau_vals[i].value().to_u32().unwrap() != 1 {
            println!("Client {}, {} != {}", i, hex::encode(h0), hex::encode(h1));
            verified[i] = false;
        }
    }

    let req = HistogramAddLeavesBetweenClientsRequest { verified: verified };
    let response0 = client0.histogram_add_leaves_between_clients(long_context(), req.clone());
    let response1 = client1.histogram_add_leaves_between_clients(long_context(), req);
    let (s0, s1) = try_join!(response0, response1).unwrap();

    for res in &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &s0, &s1
    ) {
        let bits = dpf_codes::bits_to_bitstring(&res.path);
        println!("Value ({}) \t Count: {:?}", bits, res.value.value());
    }

    Ok(hashes0.len())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);

    let transport0 = tarpc::serde_transport::tcp::connect(cfg.server0, Json::default);
    let transport1 = tarpc::serde_transport::tcp::connect(cfg.server1, Json::default);

    let mut client0 = dpf_codes::HistogramCollectorClient::new(
        client::Config::default(), transport0.await?
    ).spawn();
    let mut client1 = dpf_codes::HistogramCollectorClient::new(
        client::Config::default(), transport1.await?
    ).spawn();

    let start = Instant::now();
    let (keys0, keys1) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys0.len(),
        delta,
        delta / (keys0.len() as f64)
    );

    reset_servers(&mut client0, &mut client1).await?;

    let mut left_to_go = nreqs;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut resps = vec![];

        for _j in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.addkey_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                resps.push(add_keys(
                    &cfg,
                    client0.clone(),
                    client1.clone(),
                    &keys0,
                    &keys1,
                    this_batch,
                ));
            }
        }

        for r in resps {
            r.await?;
        }
    }

    tree_init(&mut client0, &mut client1).await?;

    let start = Instant::now();
    let bitlen = cfg.data_len * 8; // bits
    for level in 0..bitlen-1 {
        let active_paths = run_level(&mut client0, &mut client1, level, start).await?;

        println!(
            "Level {:?} active_paths={:?} {:?}",
            level,
            active_paths,
            start.elapsed().as_secs_f64()
        );
    }

    let active_paths = run_level_last(&mut client0, &mut client1, start).await?;
    println!(
        "Level {:?} active_paths={:?} {:?}",
        bitlen,
        active_paths,
        start.elapsed().as_secs_f64()
    );

    Ok(())
}
