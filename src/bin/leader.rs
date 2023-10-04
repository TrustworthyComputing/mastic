use mastic::{
    collect, config, dpf, fastfield,
    rpc::{
        AddKeysRequest, AddLeavesBetweenClientsRequest, ComputeHashesRequest, ResetRequest,
        TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    FieldElm, HHCollectorClient,
};

use futures::try_join;

use num_traits::cast::ToPrimitive;
use rand::{distributions::Alphanumeric, Rng};
use rayon::prelude::*;
use std::{
    io,
    time::{Duration, Instant, SystemTime},
};
use tarpc::{client, context, serde_transport::tcp, tokio_serde::formats::Bincode};

type Key = dpf::DPFKey<fastfield::FE, FieldElm>;
type Client = HHCollectorClient;

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
    let (keys01, keys10): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .map(|_| dpf::DPFKey::gen_from_str(&sample_string(cfg.data_bytes * 8)))
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys01[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    (keys01, keys10)
}

async fn reset_servers(client_0: &Client, client_1: &Client) -> io::Result<()> {
    // responses.push(client_0.reset(long_context(), ResetRequest {  }));

    let req = ResetRequest {};
    let response_0 = client_0.reset(long_context(), req.clone());
    let response_1 = client_1.reset(long_context(), req);
    try_join!(response_0, response_1).unwrap();

    Ok(())
}

async fn tree_init(client_0: &Client, client_1: &Client) -> io::Result<()> {
    let req = TreeInitRequest {};
    let response0 = client_0.tree_init(long_context(), req.clone());
    let response1 = client_1.tree_init(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    keys_0: &[dpf::DPFKey<fastfield::FE, FieldElm>],
    keys_1: &[dpf::DPFKey<fastfield::FE, FieldElm>],
    nreqs: usize,
    malicious_percentage: f32,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkeys_0 = Vec::with_capacity(nreqs);
    let mut addkeys_1 = Vec::with_capacity(nreqs);

    for r in 0..nreqs {
        let idx_1 = zipf.sample(&mut rng) - 1;
        let mut idx_2 = idx_1;
        if rand::thread_rng().gen_range(0.0..1.0) < malicious_percentage {
            idx_2 += 1;
            println!("Malicious {}", r);
        }

        addkeys_0.push(keys_0[idx_1].clone());
        addkeys_1.push(keys_1[idx_2 % cfg.unique_buckets].clone());
    }

    let resp_0 = client_0.add_keys(long_context(), AddKeysRequest { keys: addkeys_0 });
    let resp_1 = client_1.add_keys(long_context(), AddKeysRequest { keys: addkeys_1 });
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    nreqs: usize,
) -> io::Result<()> {
    let threshold64 = core::cmp::max(1, (cfg.threshold * (nreqs as f64)) as u64);
    let threshold = fastfield::FE::new(threshold64 as u64);
    let mut keep;
    let mut split = 1usize;
    let mut malicious = Vec::<usize>::new();
    let mut is_last = false;
    loop {
        let ml = malicious.clone();
        let req = TreeCrawlRequest {
            split_by: split,
            malicious: ml,
            is_last,
        };

        let response0 = client_0.tree_crawl(long_context(), req.clone());
        let response1 = client_1.tree_crawl(long_context(), req);
        let ((vals_0, root0, indices0), (vals_1, root1, _)) =
            try_join!(response0, response1).unwrap();

        assert_eq!(vals_0.len(), vals_1.len());
        keep = collect::KeyCollection::<fastfield::FE, FieldElm>::keep_values(
            &threshold, &vals_0, &vals_1,
        );

        if root0[0].is_empty() {
            break;
        }
        let left_root0 = &root0[0];
        let left_root1 = &root1[0];
        malicious = Vec::new();
        for i in 0..left_root0.len() {
            let hl0 = &left_root0[i]
                .iter()
                .map(|x| format!("{:02x}", x))
                .collect::<String>();
            let hl1 = &left_root1[i]
                .iter()
                .map(|x| format!("{:02x}", x))
                .collect::<String>();
            if hl0 != hl1 {
                malicious.push(indices0[0][i]);
                // println!("{}) different {} vs {}", i, hl0, hl1);
            }
        }
        if malicious.is_empty() {
            break;
        } else {
            // println!("Detected malicious {:?} out of {} clients", malicious, nreqs);
            if split > nreqs {
                if !is_last {
                    is_last = true;
                } else {
                    break;
                }
            }
            split *= 2;
        }
    }

    // Tree prune
    let req = TreePruneRequest { keep };
    let response0 = client_0.tree_prune(long_context(), req.clone());
    let response1 = client_1.tree_prune(long_context(), req);
    try_join!(response0, response1).unwrap();

    Ok(())
}

async fn run_level_last(
    client_0: &Client,
    client_1: &Client,
    num_clients: usize,
) -> io::Result<()> {
    let req = TreeCrawlLastRequest {};
    let response0 = client_0.tree_crawl_last(long_context(), req.clone());
    let response1 = client_1.tree_crawl_last(long_context(), req);
    let ((hashes_0, tau_vals_0), (hashes_1, tau_vals_1)) = try_join!(response0, response1).unwrap();

    assert_eq!(hashes_0.len(), hashes_1.len());

    let mut ver_0 = vec![true; num_clients];
    mastic::check_hashes(&mut ver_0, &hashes_0, &hashes_1);
    // println!("1: ver_0 {:?}", ver_0);

    // mastic::check_taus(&mut ver_0, &tau_vals_0, &tau_vals_1);
    // println!("2: ver_0 {:?}", ver_0);

    let tau_vals_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_0,
        &tau_vals_1,
    );

    // Check s0, s1 hashes and taus
    mastic::check_hashes_and_taus(&mut ver_0, &hashes_0, &hashes_1, tau_vals_0, num_clients);
    assert!(ver_0.iter().all(|&x| x));

    let req = ComputeHashesRequest {};
    let response0 = client_0.compute_hashes(long_context(), req.clone());
    let response1 = client_1.compute_hashes(long_context(), req);
    let (hashes_0, hashes_1) = try_join!(response0, response1).unwrap();
    mastic::check_hashes(&mut ver_0, &hashes_0, &hashes_1);

    // TODO: prune last

    let req = AddLeavesBetweenClientsRequest { verified: ver_0 };
    let response0 = client_0.add_leaves_between_clients(long_context(), req.clone());
    let response1 = client_1.add_leaves_between_clients(long_context(), req);
    let (shares_00, shares_01) = try_join!(response0, response1).unwrap();

    for res in
        &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(&shares_00, &shares_01)
    {
        let bits = mastic::bits_to_bitstring(&res.path);
        if res.value.value().to_u32().unwrap() > 0 {
            println!("Value ({}) \t Count: {:?}", bits, res.value.value());
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // println!("Using only one thread!");
    // rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    let (cfg, _, nreqs, malicious) = config::get_args("Leader", false, true, true);
    assert!((0.0..0.8).contains(&malicious));
    println!("Running with {}% malicious clients", malicious * 100.0);
    let client_0 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_0, Bincode::default).await?,
    )
    .spawn();
    let client_1 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_1, Bincode::default).await?,
    )
    .spawn();

    let start = Instant::now();
    println!("Generating keys...");
    let (keys_0, keys_1) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys_0.len(),
        delta,
        delta / (keys_0.len() as f64)
    );

    reset_servers(&client_0, &client_1).await?;

    let mut left_to_go = nreqs;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut resps = vec![];

        for _ in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.addkey_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                resps.push(add_keys(
                    &cfg, &client_0, &client_1, &keys_0, &keys_1, this_batch, malicious,
                ));
            }
        }

        for r in resps {
            r.await?;
        }
    }

    tree_init(&client_0, &client_1).await?;

    let start = Instant::now();
    let bitlen = cfg.data_bytes * 8; // bits
    for _level in 0..bitlen - 1 {
        let start_level = Instant::now();
        run_level(&cfg, &client_0, &client_1, nreqs).await?;
        println!(
            "Time for level {}: {:?}",
            _level,
            start_level.elapsed().as_secs_f64()
        );
    }
    println!(
        "\nTime for {} levels: {:?}",
        bitlen,
        start.elapsed().as_secs_f64()
    );

    let start_last = Instant::now();
    run_level_last(&client_0, &client_1, nreqs).await?;
    println!(
        "Time for last level: {:?}",
        start_last.elapsed().as_secs_f64()
    );
    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
