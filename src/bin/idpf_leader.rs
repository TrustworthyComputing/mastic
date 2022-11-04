use dpf_codes::{
    bits_to_string,
    collect,
    config,
    dpf,
    encode,
    FieldElm,
    fastfield,
    idpf_rpc::{
        IdpfAddKeysRequest,
        IdpfFinalSharesRequest,
        IdpfResetRequest, 
        IdpfTreeInitRequest,
        IdpfTreeCrawlRequest, 
        IdpfTreeCrawlLastRequest, 
        IdpfTreePruneRequest, 
        IdpfTreePruneLastRequest, 
    },
};

use geo::Point;

use futures::try_join;
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

fn _sample_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len / 8)
        .collect()
}

fn sample_location() -> (f64, f64) {
    let mut rng = rand::thread_rng();
    (rng.gen_range(-180.0..180.0) as f64, rng.gen_range(-90.0..90.0) as f64)
}

fn generate_keys(cfg: &config::Config) -> (Vec<Key>, Vec<Key>) {
    println!("data_len = {}\n", cfg.data_len);

    let (keys0, keys1): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .map(|_| {
            let loc = sample_location();
            let data_string = encode(Point::new(loc.0, loc.1), cfg.data_len * 8);
        
            println!("data_string = {}", data_string);
            
            dpf::DPFKey::gen_from_str(&data_string)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys0[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    (keys0, keys1)
}

async fn reset_servers(
    client0: &mut dpf_codes::IdpfCollectorClient,
    client1: &mut dpf_codes::IdpfCollectorClient,
) -> io::Result<()> {
    let req = IdpfResetRequest {};
    let response0 = client0.reset(long_context(), req.clone());
    let response1 = client1.reset(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn tree_init(
    client0: &mut dpf_codes::IdpfCollectorClient,
    client1: &mut dpf_codes::IdpfCollectorClient,
) -> io::Result<()> {
    let req = IdpfTreeInitRequest {};
    let response0 = client0.tree_init(long_context(), req.clone());
    let response1 = client1.tree_init(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    client0: dpf_codes::IdpfCollectorClient,
    client1: dpf_codes::IdpfCollectorClient,
    keys0: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    keys1: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    nreqs: usize,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkey0 = Vec::with_capacity(nreqs);
    let mut addkey1 = Vec::with_capacity(nreqs);

    for _j in 0..nreqs {
        let sample = zipf.sample(&mut rng) - 1;
        addkey0.push(keys0[sample].clone());
        addkey1.push(keys1[sample].clone());
    }

    let req0 = IdpfAddKeysRequest { keys: addkey0 };
    let req1 = IdpfAddKeysRequest { keys: addkey1 };

    let response0 = client0.add_keys(long_context(), req0.clone());
    let response1 = client1.add_keys(long_context(), req1.clone());

    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    client0: &mut dpf_codes::IdpfCollectorClient,
    client1: &mut dpf_codes::IdpfCollectorClient,
    level: usize,
    nreqs: usize,
    start_time: Instant,
) -> io::Result<usize> {
    let threshold64 = core::cmp::max(1, (cfg.threshold * (nreqs as f64)) as u64);
    let threshold = fastfield::FE::new(threshold64 as u64);

    // Tree crawl
    println!(
        "TreeCrawlStart {:?} {:?} {:?}",
        level,
        "-",
        start_time.elapsed().as_secs_f64()
    );
    let req = IdpfTreeCrawlRequest {};
    let response0 = client0.tree_crawl(long_context(), req.clone());
    let response1 = client1.tree_crawl(long_context(), req);
    let (vals0, vals1) = try_join!(response0, response1).unwrap();
    println!(
        "TreeCrawlDone {:?} {:?} {:?}",
        level,
        "-",
        start_time.elapsed().as_secs_f64()
    );

    assert_eq!(vals0.len(), vals1.len());
    let keep = collect::KeyCollection::<fastfield::FE,FieldElm>::keep_values(nreqs, &threshold, &vals0, &vals1);
    //println!("Keep: {:?}", keep);
    //println!("KeepLen: {:?}", keep.len());

    // Tree prune
    let req = IdpfTreePruneRequest { keep };
    let response0 = client0.tree_prune(long_context(), req.clone());
    let response1 = client1.tree_prune(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(vals0.len())
}

async fn run_level_last(
    cfg: &config::Config,
    client0: &mut dpf_codes::IdpfCollectorClient,
    client1: &mut dpf_codes::IdpfCollectorClient,
    nreqs: usize,
    start_time: Instant,
) -> io::Result<usize> {
    let threshold64 = core::cmp::max(1, (cfg.threshold * (nreqs as f64)) as u32);
    let threshold = FieldElm::from(threshold64 as u32);

    // Tree crawl
    println!(
        "TreeCrawlStart last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );
    let req = IdpfTreeCrawlLastRequest {};
    let response0 = client0.tree_crawl_last(long_context(), req.clone());
    let response1 = client1.tree_crawl_last(long_context(), req);
    let (vals0, vals1) = try_join!(response0, response1).unwrap();
    println!(
        "TreeCrawlDone last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );

    assert_eq!(vals0.len(), vals1.len());
    let keep = collect::KeyCollection::<fastfield::FE,FieldElm>::keep_values_last(nreqs, &threshold, &vals0, &vals1);
    //println!("Keep: {:?}", keep);
    //println!("KeepLen: {:?}", keep.len());

    // Tree prune
    let req = IdpfTreePruneLastRequest { keep };
    let response0 = client0.tree_prune_last(long_context(), req.clone());
    let response1 = client1.tree_prune_last(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(vals0.len())
}

async fn final_shares(
    client0: &mut dpf_codes::IdpfCollectorClient,
    client1: &mut dpf_codes::IdpfCollectorClient,
) -> io::Result<()> {
    // Final shares
    let req = IdpfFinalSharesRequest {};
    let response0 = client0.final_shares(long_context(), req.clone());
    let response1 = client1.final_shares(long_context(), req);
    let (out_shares0, out_shares1) = try_join!(response0, response1).unwrap();

    for res in &collect::KeyCollection::<fastfield::FE,FieldElm>::final_values(&out_shares0, &out_shares1) {
        // println!("Path = {:?}", res.path);
        let s = crate::bits_to_string(&res.path);
        println!("Value: {:?} = {:?}", s, res.value);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);
    debug_assert_eq!(cfg.data_len % 8, 0);

    let transport0 = tarpc::serde_transport::tcp::connect(cfg.server_0, Json::default);
    let transport1 = tarpc::serde_transport::tcp::connect(cfg.server_1, Json::default);

    let mut client0 = dpf_codes::IdpfCollectorClient::new(
        client::Config::default(), transport0.await?
    ).spawn();
    let mut client1 = dpf_codes::IdpfCollectorClient::new(
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
        let active_paths = run_level(&cfg, &mut client0, &mut client1, level, nreqs, start).await?;

        println!(
            "Level {:?} active_paths={:?} {:?}",
            level,
            active_paths,
            start.elapsed().as_secs_f64()
        );
    }

    let active_paths = run_level_last(&cfg, &mut client0, &mut client1, nreqs, start).await?;
    println!(
        "Level {:?} active_paths={:?} {:?}",
        bitlen,
        active_paths,
        start.elapsed().as_secs_f64()
    );

    final_shares(&mut client0, &mut client1).await?;

    Ok(())
}
