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
    HistogramCollectorClient,
};

use futures::try_join;
use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use rand::{Rng, distributions::Alphanumeric,};
use rayon::prelude::*;
use std::{io, time::{Duration, SystemTime, Instant},};
use tarpc::{client, context, tokio_serde::formats::Json, serde_transport::tcp,};

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
    clients: &mut Vec<Client>,
) -> io::Result<()> {
    for client in clients.iter() {
        let response_0 = client.0.reset(
            long_context(), HistogramResetRequest { client_idx: 0 }
        );
        let response_1 = client.1.reset(
            long_context(), HistogramResetRequest { client_idx: 1 }
        );
        try_join!(response_0, response_1).unwrap();
    }

    Ok(())
}

async fn tree_init(
    clients: &mut Vec<Client>,
) -> io::Result<()> {
    for client in clients.iter() {
        let response_0 = client.0.tree_init(
            long_context(), HistogramTreeInitRequest { client_idx: 0 }
        );
        let response_1 = client.1.tree_init(
            long_context(), HistogramTreeInitRequest { client_idx: 1 }
        );
        try_join!(response_0, response_1).unwrap();
    }

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    clients: &Vec<Client>,
    keys0: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    keys1: &[dpf::DPFKey<fastfield::FE,FieldElm>],
    nreqs: usize,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkey_00 = Vec::with_capacity(nreqs);
    let mut addkey_01 = Vec::with_capacity(nreqs);

    for _ in 0..nreqs {
        let idx = zipf.sample(&mut rng) - 1;
        addkey_00.push(keys0[idx].clone());
        addkey_01.push(keys1[idx].clone());
    }

    for client in clients.iter() {
        let response_0 = client.0.add_keys(
            long_context(),
            HistogramAddKeysRequest { client_idx: 0, keys: addkey_00.clone() }
        );
        let response_1 = client.1.add_keys(
            long_context(),
            HistogramAddKeysRequest { client_idx: 1, keys: addkey_01.clone() }
        );
        try_join!(response_0, response_1).unwrap();
    }

    Ok(())
}

async fn run_level(
    clients: &mut Vec<Client>,
    _level: usize,
    _start_time: Instant,
) -> io::Result<()> {
    // Tree crawl
    // println!(
    //     "TreeCrawlStart {:?} - {:?}", _level, _start_time.elapsed().as_secs_f64()
    // );
    for client in clients.iter() {
        let response_0 = client.0.histogram_tree_crawl(
            long_context(), HistogramTreeCrawlRequest { client_idx: 0 }
        );
        let response_1 = client.1.histogram_tree_crawl(
            long_context(), HistogramTreeCrawlRequest { client_idx: 1 }
        );
        let (vals_0, vals_1) = try_join!(response_0, response_1).unwrap();
        assert_eq!(vals_0.len(), vals_1.len());
    }
    
    // println!(
    //     "TreeCrawlDone {:?} - {:?}", _level, _start_time.elapsed().as_secs_f64()
    // );

    Ok(())
}

async fn run_level_last(
    clients: &mut Vec<Client>,
    _start_time: Instant,
) -> io::Result<()> {
    // Tree crawl
    // println!("TreeCrawlStart last {:?}", _start_time.elapsed().as_secs_f64());
    let response_00 = clients[0].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_01 = clients[0].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_00, tau_vals_00), (hashes_01, tau_vals_01)) = 
        try_join!(response_00, response_01).unwrap();
    assert_eq!(hashes_00.len(), hashes_01.len());
    let response_11 = clients[1].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_12 = clients[1].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_11, tau_vals_11), (hashes_12, tau_vals_12)) = 
        try_join!(response_11, response_12).unwrap();
    assert_eq!(hashes_11.len(), hashes_12.len());
        
    let response_22 = clients[2].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_20 = clients[2].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_22, tau_vals_22), (hashes_20, tau_vals_20)) = 
        try_join!(response_22, response_20).unwrap();
    assert_eq!(hashes_11.len(), hashes_12.len());
    // println!("TreeCrawlDone last - {:?}", _start_time.elapsed().as_secs_f64());
    let mut ver_0 = vec![true; hashes_00.len()];
    let mut ver_1 = vec![true; hashes_11.len()];
    let mut ver_2 = vec![true; hashes_22.len()];

    let tau_vals_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_00, &tau_vals_01
    );
    let tau_vals_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_11, &tau_vals_12
    );
    let tau_vals_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_22, &tau_vals_20
    );

    // Check s0, s1 hashes and taus
    for ((i, h0), h1) in hashes_00.iter().enumerate().zip_eq(hashes_01) {
        let matching = h0.iter().zip(h1.iter()).filter(|&(h0, h1)| h0 == h1).count();
        if h0.len() != matching || tau_vals_0[i].value().to_u32().unwrap() != 1 {
            println!("Client {}, {} != {}", i, hex::encode(h0), hex::encode(h1));
            ver_0[i] = false;
        }
    }
    // Check s1, s2 hashes and taus
    for ((i, h0), h1) in hashes_11.iter().enumerate().zip_eq(hashes_12) {
        let matching = h0.iter().zip(h1.iter()).filter(|&(h0, h1)| h0 == h1).count();
        if h0.len() != matching || tau_vals_1[i].value().to_u32().unwrap() != 1 {
            println!("Client {}, {} != {}", i, hex::encode(h0), hex::encode(h1));
            ver_1[i] = false;
        }
    }
    // Check s2, s0 hashes and taus
    for ((i, h0), h1) in hashes_22.iter().enumerate().zip_eq(hashes_20) {
        let matching = h0.iter().zip(h1.iter()).filter(|&(h0, h1)| h0 == h1).count();
        if h0.len() != matching || tau_vals_2[i].value().to_u32().unwrap() != 1 {
            println!("Client {}, {} != {}", i, hex::encode(h0), hex::encode(h1));
            ver_2[i] = false;
        }
    }
    assert_eq!(ver_0.iter().zip(ver_1.iter()).filter(|&(v0, v1)| v0 == v1).count(), ver_0.len());

    let response_00 = clients[0].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_0.clone() }
    );
    let response_01 = clients[0].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_0 }
    );
    let (shares_00, shares_01) = try_join!(response_00, response_01).unwrap();

    let response_11 = clients[1].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_1.clone() }
    );
    let response_12 = clients[1].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_1 }
    );
    let (shares_11, shares_12) = try_join!(response_11, response_12).unwrap();
    
    let response_22 = clients[2].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_2.clone() }
    );
    let response_20 = clients[2].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_2 }
    );
    let (shares_22, shares_20) = try_join!(response_22, response_20).unwrap();

    let hist_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_00, &shares_01
    );
    let hist_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_11, &shares_12
    );
    let hist_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_22, &shares_20
    );

    for ((res_0, res_1), res_2) in hist_0.iter().zip_eq(hist_1).zip_eq(hist_2) {
        assert_eq!(res_0.value.value(), res_1.value.value());
        assert_eq!(res_0.value.value(), res_2.value.value());
        let bits = dpf_codes::bits_to_bitstring(&res_0.path);
        println!("Value ({}) \t Count: {:?}", bits, res_0.value.value());
    }
    Ok(())
}

// Client/Server Pairs: 
// Client 0 connects to S0 and S1
// Client 1 connects to S1 and S2
// Client 2 connects to S2 and S0

type Client = (HistogramCollectorClient, HistogramCollectorClient);

#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);

    let client_0: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_0, Json::default).await?
        ).spawn(),
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_1, Json::default).await?
        ).spawn()
    );
    let client_1: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_1, Json::default).await?
        ).spawn(),
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_2, Json::default).await?
        ).spawn()
    );
    let client_2: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_2, Json::default).await?
        ).spawn(), 
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_0, Json::default).await?
        ).spawn()
    );
    let mut clients = vec![client_0, client_1, client_2];

    let start = Instant::now();
    let (keys0, keys1) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys0.len(), delta, delta / (keys0.len() as f64)
    );

    reset_servers(&mut clients).await?;

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
                    &clients,
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

    tree_init(&mut clients).await?;

    let start = Instant::now();
    let bitlen = cfg.data_len * 8; // bits
    for level in 0..bitlen-1 {
        run_level(&mut clients, level, start).await?;
        // println!("Level {:?}: {:?}", level, start.elapsed().as_secs_f64());
    }

    run_level_last(&mut clients, start).await?;
    println!("Level {:?}: {:?}", bitlen, start.elapsed().as_secs_f64());

    Ok(())
}
