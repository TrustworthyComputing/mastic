use std::{
    io,
    time::{Duration, Instant, SystemTime},
};

use futures::try_join;
use mastic::{
    collect, config, dpf,
    rpc::{
        AddFLPsRequest, AddKeysRequest, ApplyFLPResultsRequest, FinalSharesRequest,
        GetProofsRequest, ResetRequest, RunFlpQueriesRequest, TreeCrawlLastRequest,
        TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    CollectorClient,
};
use prio::{
    field::{random_vector, Field64},
    flp::{types::Count, Type},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rayon::prelude::*;
use tarpc::{client, context, serde_transport::tcp, tokio_serde::formats::Bincode};

type Key = dpf::DPFKey<Field64>;
type Client = CollectorClient;

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

fn generate_keys(
    cfg: &config::Config,
) -> ((Vec<Key>, Vec<Key>), (Vec<Vec<Field64>>, Vec<Vec<Field64>>)) {
    let beta = 1u64;
    let count = Count::new();
    let input_beta: Vec<Field64> = count.encode_measurement(&beta).unwrap();

    let (keys_0, keys_1): (Vec<Key>, Vec<Key>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .map(|_| dpf::DPFKey::gen_from_str(&sample_string(cfg.data_bytes * 8), Field64::from(beta)))
        .unzip();

    let (proofs_0, proofs_1): (Vec<Vec<Field64>>, Vec<Vec<Field64>>) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .map(|_| {
            let prove_rand = random_vector(count.prove_rand_len()).unwrap();
            let proof = count.prove(&input_beta, &prove_rand, &[]).unwrap();

            let proof_0 = proof
                .iter()
                .map(|_| Field64::from(rand::thread_rng().gen::<u64>()))
                .collect::<Vec<_>>();
            let proof_1 = proof
                .par_iter()
                .zip(proof_0.par_iter())
                .map(|(p_0, p_1)| p_0 - p_1)
                .collect::<Vec<_>>();
            (proof_0, proof_1)
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys_0[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    ((keys_0, keys_1), (proofs_0, proofs_1))
}

async fn reset_servers(
    client_0: &Client,
    client_1: &Client,
    verify_key: &[u8; 16],
) -> io::Result<()> {
    let req = ResetRequest {
        verify_key: *verify_key,
    };
    let resp_0 = client_0.reset(long_context(), req.clone());
    let resp_1 = client_1.reset(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn tree_init(client_0: &Client, client_1: &Client) -> io::Result<()> {
    let req = TreeInitRequest {};
    let resp_0 = client_0.tree_init(long_context(), req.clone());
    let resp_1 = client_1.tree_init(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    keys_0: &[dpf::DPFKey<Field64>],
    keys_1: &[dpf::DPFKey<Field64>],
    proofs_0: &[Vec<Field64>],
    proofs_1: &[Vec<Field64>],
    num_clients: usize,
    malicious_percentage: f32,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut add_keys_0 = Vec::with_capacity(num_clients);
    let mut add_keys_1 = Vec::with_capacity(num_clients);
    let mut flp_proof_shares_0 = Vec::with_capacity(num_clients);
    let mut flp_proof_shares_1 = Vec::with_capacity(num_clients);
    for r in 0..num_clients {
        let idx_1 = zipf.sample(&mut rng) - 1;
        let mut idx_2 = idx_1;
        let mut idx_3 = idx_1;
        if rng.gen_range(0.0..1.0) < malicious_percentage {
            if rng.gen() {
                // Malicious key.
                idx_2 += 1;
            } else {
                // Malicious FLP.
                idx_3 += 1;
            }
            println!("Malicious {}", r);
        }
        add_keys_0.push(keys_0[idx_1].clone());
        add_keys_1.push(keys_1[idx_2 % cfg.unique_buckets].clone());

        flp_proof_shares_0.push(proofs_0[idx_1].clone());
        flp_proof_shares_1.push(proofs_1[idx_3 % cfg.unique_buckets].clone());
    }

    let resp_0 = client_0.add_keys(long_context(), AddKeysRequest { keys: add_keys_0 });
    let resp_1 = client_1.add_keys(long_context(), AddKeysRequest { keys: add_keys_1 });
    try_join!(resp_0, resp_1).unwrap();

    let resp_0 = client_0.add_all_flp_proof_shares(
        long_context(),
        AddFLPsRequest {
            flp_proof_shares: flp_proof_shares_0,
        },
    );
    let resp_1 = client_1.add_all_flp_proof_shares(
        long_context(),
        AddFLPsRequest {
            flp_proof_shares: flp_proof_shares_1,
        },
    );
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_flp_queries(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    num_clients: usize,
) -> io::Result<()> {
    // Receive FLP query responses in chunks of cfg.flp_batch_size to avoid having huge RPC messages.
    let count = Count::new();
    let mut keep = vec![];
    let mut start = 0;
    while start < num_clients {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);

        let req = RunFlpQueriesRequest { start, end };
        let resp_0 = client_0.run_flp_queries(long_context(), req.clone());
        let resp_1 = client_1.run_flp_queries(long_context(), req);
        let (flp_verifier_shares_0, flp_verifier_shares_1) = try_join!(resp_0, resp_1).unwrap();
        debug_assert_eq!(flp_verifier_shares_0.len(), flp_verifier_shares_1.len());

        keep.extend(
            flp_verifier_shares_0
                .par_iter()
                .zip(flp_verifier_shares_1.par_iter())
                .map(|(flp_verifier_share_0, flp_verifier_share_1)| {
                    let flp_verifier = flp_verifier_share_0
                        .par_iter()
                        .zip(flp_verifier_share_1.par_iter())
                        .map(|(&v1, &v2)| v1 + v2)
                        .collect::<Vec<_>>();

                    count.decide(&flp_verifier).unwrap()
                })
                .collect::<Vec<_>>(),
        );

        start += cfg.flp_batch_size;
    }

    // Tree prune
    let req = ApplyFLPResultsRequest { keep };
    let resp_0 = client_0.apply_flp_results(long_context(), req.clone());
    let resp_1 = client_1.apply_flp_results(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    num_clients: usize,
) -> io::Result<()> {
    let threshold = core::cmp::max(1, (cfg.threshold * (num_clients as f64)) as u64);
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

        let resp_0 = client_0.tree_crawl(long_context(), req.clone());
        let resp_1 = client_1.tree_crawl(long_context(), req);
        let ((cnt_values_0, mt_root_0, indices_0), (cnt_values_1, mt_root_1, indices_1)) =
            try_join!(resp_0, resp_1).unwrap();

        assert_eq!(cnt_values_0.len(), cnt_values_1.len());
        keep =
            collect::KeyCollection::<Field64>::keep_values(threshold, &cnt_values_0, &cnt_values_1);
        if mt_root_0.is_empty() {
            break;
        }

        malicious = Vec::new();
        for i in 0..mt_root_0.len() {
            if mt_root_0[i] != mt_root_1[i] {
                assert_eq!(indices_0[i], indices_1[i]);
                malicious.push(indices_0[i]);
                // println!("{}) different {} vs {}", i, hl0, hl1);
            }
        }
        if malicious.is_empty() {
            break;
        } else {
            println!(
                "Detected malicious {:?} out of {} clients",
                malicious, num_clients
            );
            if split >= num_clients {
                if is_last {
                    break;
                } else {
                    is_last = true;
                }
            } else {
                split *= 2;
            }
        }
    }

    // Tree prune
    let req = TreePruneRequest { keep };
    let resp_0 = client_0.tree_prune(long_context(), req.clone());
    let resp_1 = client_1.tree_prune(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    Ok(())
}

async fn run_level_last(
    cfg: &config::Config,
    client_0: &Client,
    client_1: &Client,
    num_clients: usize,
) -> io::Result<()> {
    let threshold = core::cmp::max(1, (cfg.threshold * (num_clients as f64)) as u64);

    let req = TreeCrawlLastRequest {};
    let resp_0 = client_0.tree_crawl_last(long_context(), req.clone());
    let resp_1 = client_1.tree_crawl_last(long_context(), req);
    let (cnt_values_0, cnt_values_1) = try_join!(resp_0, resp_1).unwrap();
    assert_eq!(cnt_values_0.len(), cnt_values_1.len());
    let keep =
        collect::KeyCollection::<Field64>::keep_values(threshold, &cnt_values_0, &cnt_values_1);

    // Receive counters in chunks to avoid having huge RPC messages.
    let mut start = 0;
    while start < num_clients {
        let end = std::cmp::min(num_clients, start + cfg.flp_batch_size);

        let req = GetProofsRequest { start, end };
        let resp_0 = client_0.get_proofs(long_context(), req.clone());
        let resp_1 = client_1.get_proofs(long_context(), req);
        let (hashes_0, hashes_1) = try_join!(resp_0, resp_1).unwrap();

        assert_eq!(hashes_0.len(), hashes_1.len());

        let verified = hashes_0
            .par_iter()
            .zip(hashes_1.par_iter())
            .all(|(&h0, &h1)| h0 == h1);
        assert!(verified);

        start += cfg.flp_batch_size;
    }

    // Tree prune
    let req = TreePruneRequest { keep };
    let resp_0 = client_0.tree_prune(long_context(), req.clone());
    let resp_1 = client_1.tree_prune(long_context(), req);
    try_join!(resp_0, resp_1).unwrap();

    let req = FinalSharesRequest {};
    let resp_0 = client_0.final_shares(long_context(), req.clone());
    let resp_1 = client_1.final_shares(long_context(), req);
    let (shares_0, shares_1) = try_join!(resp_0, resp_1).unwrap();
    for res in &collect::KeyCollection::<Field64>::final_values(&shares_0, &shares_1) {
        let bits = mastic::bits_to_bitstring(&res.path);
        if res.value > Field64::from(0) {
            println!("Value ({}) \t Count: {:?}", bits, res.value);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // println!("Using only one thread!");
    // rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    let (cfg, _, num_clients, malicious) = config::get_args("Leader", false, true, true);
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
    let ((keys_0, keys_1), (proofs_0, proofs_1)) = generate_keys(&cfg);
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys_0.len(),
        delta,
        delta / (keys_0.len() as f64)
    );

    let mut verify_key = [0; 16];
    thread_rng().fill(&mut verify_key);

    reset_servers(&client_0, &client_1, &verify_key).await?;

    let mut left_to_go = num_clients;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut responses = vec![];

        for _ in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.add_key_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                responses.push(add_keys(
                    &cfg, &client_0, &client_1, &keys_0, &keys_1, &proofs_0, &proofs_1, this_batch,
                    malicious,
                ));
            }
        }

        for r in responses {
            r.await?;
        }
    }

    tree_init(&client_0, &client_1).await?;

    let start = Instant::now();
    let bit_len = cfg.data_bytes * 8; // bits
    for level in 0..bit_len - 1 {
        let start_level = Instant::now();
        if level == 0 {
            run_flp_queries(&cfg, &client_0, &client_1, num_clients).await?;
        }
        run_level(&cfg, &client_0, &client_1, num_clients).await?;
        println!(
            "Time for level {}: {:?}",
            level,
            start_level.elapsed().as_secs_f64()
        );
    }
    println!(
        "\nTime for {} levels: {:?}",
        bit_len,
        start.elapsed().as_secs_f64()
    );

    let start_last = Instant::now();
    run_level_last(&cfg, &client_0, &client_1, num_clients).await?;
    println!(
        "Time for last level: {:?}",
        start_last.elapsed().as_secs_f64()
    );
    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
