use dpf_codes::{
    FieldElm,
    collect, config, fastfield,
    histogram_rpc::{
        HistogramAddKeysRequest,
        HistogramFinalSharesRequest,
        HistogramResetRequest, 
        HistogramTreeInitRequest,
        HistogramTreeCrawlRequest, 
        HistogramTreeCrawlLastRequest, 
    },
    dpf,
    bits_to_bitstring,
};

use std::time::Instant;

use futures::try_join;
use std::io;
use rand::Rng;
use rand::distributions::Alphanumeric;
use rayon::prelude::*;
use tarpc::{
    client,
    context,
};

use tokio::net::TcpStream;
use tokio_serde::formats::Bincode;

use std::time::{Duration, SystemTime};

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
    client0: &mut dpf_codes::CollectorClient,
    client1: &mut dpf_codes::CollectorClient,
) -> io::Result<()> {
    let req = HistogramResetRequest {};
    let response0 = client0.reset(long_context(), req.clone());
    let response1 = client1.reset(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn tree_init(
    client0: &mut dpf_codes::CollectorClient,
    client1: &mut dpf_codes::CollectorClient,
) -> io::Result<()> {
    let req = HistogramTreeInitRequest {};
    let response0 = client0.tree_init(long_context(), req.clone());
    let response1 = client1.tree_init(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    mut client0: dpf_codes::CollectorClient,
    mut client1: dpf_codes::CollectorClient,
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
    client0: &mut dpf_codes::CollectorClient,
    client1: &mut dpf_codes::CollectorClient,
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
    Ok(vals0.len())
}

async fn run_level_last(
    client0: &mut dpf_codes::CollectorClient,
    client1: &mut dpf_codes::CollectorClient,
    start_time: Instant,
) -> io::Result<usize> {
    // Tree crawl
    println!(
        "TreeCrawlStart last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );
    let req = HistogramTreeCrawlLastRequest {};
    let response0 = client0.tree_crawl_last(long_context(), req.clone());
    let response1 = client1.tree_crawl_last(long_context(), req);
    let (vals0, vals1) = try_join!(response0, response1).unwrap();
    println!(
        "TreeCrawlDone last {:?} {:?}",
        "-",
        start_time.elapsed().as_secs_f64()
    );

    assert_eq!(vals0.len(), vals1.len());

    Ok(vals0.len())
}

async fn final_shares(
    client0: &mut dpf_codes::CollectorClient,
    client1: &mut dpf_codes::CollectorClient,
) -> io::Result<()> {
    // Final shares
    let req = HistogramFinalSharesRequest {};
    let response0 = client0.final_shares(long_context(), req.clone());
    let response1 = client1.final_shares(long_context(), req);
    let (out_shares0, out_shares1) = try_join!(response0, response1).unwrap();

    for res in &collect::KeyCollection::<fastfield::FE,FieldElm>::final_values(&out_shares0, &out_shares1) {
        let bits = crate::bits_to_bitstring(&res.path);
        println!("Value ({}) \t Count: {:?}", bits, res.value.value());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);

    let mut builder = native_tls::TlsConnector::builder();
    // XXX THERE IS NO CERTIFICATE VALIDATION HERE!!!
    // This is just for benchmarking purposes. A real implementation would
    // have pinned certificates for the two servers and use those to encrypt.
    builder.danger_accept_invalid_certs(true);

    let cx = builder.build().unwrap();
    let cx = tokio_native_tls::TlsConnector::from(cx);

    let tcp0 = TcpStream::connect(cfg.server0).await?;
    let io0 = cx.connect("server0", tcp0).await.unwrap();
    let transport0 = tarpc::serde_transport::Transport::from((io0, Bincode::default()));

    let tcp1 = TcpStream::connect(cfg.server1).await?;
    let io1 = cx.connect("server1", tcp1).await.unwrap();
    let transport1 = tarpc::serde_transport::Transport::from((io1, Bincode::default()));

    //let transport0 = tarpc::serde_transport::tcp::connect(cfg.server0, Bincode::default()).await?;

    let mut client0 =
        dpf_codes::CollectorClient::new(client::Config::default(), transport0).spawn()?;
    let mut client1 =
        dpf_codes::CollectorClient::new(client::Config::default(), transport1).spawn()?;

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

    final_shares(&mut client0, &mut client1).await?;

    Ok(())
}
